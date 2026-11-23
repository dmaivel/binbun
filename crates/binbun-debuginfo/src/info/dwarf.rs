//! Debug information from DWARF 4 and 5 (`gimli`), in an ELF file: the binary
//! itself or its separate debug file (`objcopy --only-keep-debug`, a
//! debuginfod download). Globals are the variables outside any function
//! whose location is one address. A function's unit is the compilation
//! unit (`DW_TAG_compile_unit`, or a skeleton unit) of its source-level
//! declaration (the end of its `DW_AT_abstract_origin` and
//! `DW_AT_specification` chain: under link-time optimisation GCC puts the
//! code's DIEs in one `<artificial>` unit, their origins in each source
//! file's), else of its own DIE, named by `DW_AT_name` and
//! `DW_AT_comp_dir`; neither a compilation unit (a `dwz` partial unit):
//! none.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;

use gimli::constants::{self, DwAt, DwTag};
use gimli::{
    AttributeValue, DebugInfoOffset, DebuggingInformationEntry, EndianSlice, Expression, Operation,
    RunTimeEndian, UnitOffset,
};
use object::{Object, ObjectSection};

use crate::info::model::{
    Composite, CompositeKind, Damage, DebugModel, Encoding, Field, Function, Global, Language,
    Place, Span, Type, TypeId, Unit as SourceUnit, UnitId, Variable,
};

type R<'a> = EndianSlice<'a, RunTimeEndian>;
type Dwarf<'a> = gimli::Dwarf<R<'a>>;
type Unit<'a> = gimli::Unit<R<'a>>;
type Entry<'a> = DebuggingInformationEntry<R<'a>>;

/// How deep type references are followed before the rest is
/// [`Type::Unknown`] (damaged information can loop; real types are far
/// shallower).
const TYPE_DEPTH: u32 = 256;

/// `DW_LANG_C23` (the DWARF language codes after version 5), which gimli
/// does not name.
const DW_LANG_C23: gimli::DwLang = gimli::DwLang(0x003e);

/// Reads the DWARF of an ELF file (x86-64 or AArch64).
///
/// # Errors
///
/// If the file is no ELF file `object` reads, is for another machine, or a
/// section does not decompress. Damage inside the DWARF is reported in
/// [`DebugModel::damage`] instead.
pub fn read(data: &[u8]) -> Result<DebugModel, String> {
    let file = object::File::parse(data).map_err(|error| error.to_string())?;
    let architecture = file.architecture();
    let register_name: fn(gimli::Register) -> Option<&'static str> =
        if architecture == object::Architecture::X86_64 {
            gimli::X86_64::register_name
        } else if architecture == object::Architecture::Aarch64 {
            gimli::AArch64::register_name
        } else {
            return Err(format!("no register names for {architecture:?}"));
        };
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let sections = gimli::DwarfSections::load(|id| -> Result<Cow<'_, [u8]>, String> {
        match file.section_by_name(id.name()) {
            Some(section) => section
                .uncompressed_data()
                .map_err(|error| error.to_string()),
            None => Ok(Cow::Borrowed(&[])),
        }
    })?;
    let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));
    let mut reader = Reader {
        dwarf: &dwarf,
        units: Vec::new(),
        types: HashMap::new(),
        sources: HashMap::new(),
        model: DebugModel::default(),
        register_name,
    };
    reader.load_units();
    for index in 0..reader.units.len() {
        reader.read_functions(index);
    }
    Ok(reader.model)
}

struct Reader<'d, 'a> {
    dwarf: &'d Dwarf<'a>,
    /// The units, by their offset in `.debug_info`.
    units: Vec<(DebugInfoOffset, Unit<'a>)>,
    /// The types read, by unit and offset.
    types: HashMap<(usize, UnitOffset), TypeId>,
    /// Each unit as a compilation unit ([`Self::source_unit`]), by index.
    sources: HashMap<usize, Option<UnitId>>,
    model: DebugModel,
    register_name: fn(gimli::Register) -> Option<&'static str>,
}

/// What `DW_AT_frame_base` is.
#[derive(Clone, Copy)]
enum FrameBase {
    Cfa,
    Register(&'static str),
    Unknown,
}

/// A DIE: its unit's index and its offset there.
#[derive(Clone, Copy)]
struct At {
    unit: usize,
    offset: UnitOffset,
}

impl<'a> Reader<'_, 'a> {
    fn damage(&mut self, at: impl Into<String>, error: &impl ToString) {
        self.model.damage.push(Damage {
            at: at.into(),
            message: error.to_string(),
        });
    }

    fn load_units(&mut self) {
        let mut headers = self.dwarf.units();
        loop {
            match headers.next() {
                Ok(Some(header)) => {
                    let Some(offset) = header.offset().to_debug_info_offset(&header) else {
                        continue;
                    };
                    match self.dwarf.unit(header) {
                        Ok(unit) => self.units.push((offset, unit)),
                        Err(error) => self.damage(format!(".debug_info+{:#x}", offset.0), &error),
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    self.damage(".debug_info", &error);
                    break;
                }
            }
        }
    }

    fn unit(&self, index: usize) -> Option<&Unit<'a>> {
        self.units.get(index).map(|(_, unit)| unit)
    }

    fn entry(&self, at: At) -> Option<Entry<'a>> {
        self.unit(at.unit)?.entry(at.offset).ok()
    }

    /// Where a reference attribute's value leads.
    fn reference(&self, unit: usize, value: &AttributeValue<R<'a>>) -> Option<At> {
        if let AttributeValue::UnitRef(offset) = *value {
            return Some(At { unit, offset });
        }
        let AttributeValue::DebugInfoRef(offset) = *value else {
            return None;
        };
        let index = self
            .units
            .partition_point(|(start, _)| start.0 <= offset.0)
            .checked_sub(1)?;
        let (_, target) = self.units.get(index)?;
        Some(At {
            unit: index,
            offset: offset.to_unit_offset(&target.header)?,
        })
    }

    /// An attribute of `entry`, else of what it completes or instantiates
    /// (`DW_AT_specification`, `DW_AT_abstract_origin`), a few levels deep.
    fn inherited(
        &self,
        unit: usize,
        entry: &Entry<'a>,
        name: DwAt,
    ) -> Option<(usize, AttributeValue<R<'a>>)> {
        let mut unit = unit;
        let mut entry = Cow::Borrowed(entry);
        for _ in 0..4 {
            if let Some(value) = entry.attr_value(name) {
                return Some((unit, value));
            }
            let origin = entry
                .attr_value(constants::DW_AT_abstract_origin)
                .or_else(|| entry.attr_value(constants::DW_AT_specification))?;
            let at = self.reference(unit, &origin)?;
            unit = at.unit;
            entry = Cow::Owned(self.entry(at)?);
        }
        None
    }

    fn name(&self, unit: usize, entry: &Entry<'a>) -> Option<String> {
        let (unit, value) = self.inherited(unit, entry, constants::DW_AT_name)?;
        let name = self.dwarf.attr_string(self.unit(unit)?, value).ok()?;
        Some(name.to_string_lossy().into_owned())
    }

    /// The type an entry's `DW_AT_type` names ([`Type::Void`] without one).
    fn type_of(&mut self, unit: usize, entry: &Entry<'a>, depth: u32) -> TypeId {
        match self.inherited(unit, entry, constants::DW_AT_type) {
            Some((unit, value)) => match self.reference(unit, &value) {
                Some(at) => self.read_type(at, depth),
                None => self.push(Type::Unknown),
            },
            None => self.push(Type::Void),
        }
    }

    fn push(&mut self, ty: Type) -> TypeId {
        let id = TypeId(u32::try_from(self.model.types.len()).unwrap_or(u32::MAX));
        self.model.types.push(ty);
        id
    }

    fn read_type(&mut self, at: At, depth: u32) -> TypeId {
        if let Some(&id) = self.types.get(&(at.unit, at.offset)) {
            return id;
        }
        let Some(depth) = depth.checked_sub(1) else {
            return self.push(Type::Unknown);
        };
        let Some(entry) = self.entry(at) else {
            self.damage(
                format!("type at unit {} +{:#x}", at.unit, at.offset.0),
                &"unreadable",
            );
            return self.push(Type::Unknown);
        };
        if matches!(
            entry.tag(),
            constants::DW_TAG_const_type
                | constants::DW_TAG_volatile_type
                | constants::DW_TAG_restrict_type
                | constants::DW_TAG_atomic_type
        ) {
            // Qualifiers are looked through: `const struct s` is `struct s`.
            let target = self.type_of(at.unit, &entry, depth);
            self.types.insert((at.unit, at.offset), target);
            return target;
        }
        // Recorded before its parts are read, so a type reaching itself
        // (`struct node { struct node *next; }`) ends.
        let id = self.push(Type::Unknown);
        self.types.insert((at.unit, at.offset), id);
        let ty = self.convert(at, &entry, depth);
        if let Some(slot) = usize::try_from(id.0)
            .ok()
            .and_then(|index| self.model.types.get_mut(index))
        {
            *slot = ty;
        }
        id
    }

    fn convert(&mut self, at: At, entry: &Entry<'a>, depth: u32) -> Type {
        let unit = at.unit;
        let bytes = entry
            .attr_value(constants::DW_AT_byte_size)
            .and_then(|value| value.udata_value());
        let tag = entry.tag();
        match tag {
            constants::DW_TAG_base_type => Type::Base {
                name: self.name(unit, entry).unwrap_or_default(),
                bytes: bytes.unwrap_or(0),
                encoding: encoding(entry),
            },
            constants::DW_TAG_pointer_type
            | constants::DW_TAG_reference_type
            | constants::DW_TAG_rvalue_reference_type => {
                let address = self
                    .unit(unit)
                    .map_or(8, |unit| u64::from(unit.header.address_size()));
                Type::Pointer {
                    target: self.type_of(unit, entry, depth),
                    bytes: bytes.unwrap_or(address),
                }
            }
            constants::DW_TAG_typedef => Type::Typedef {
                name: self.name(unit, entry).unwrap_or_default(),
                target: self.type_of(unit, entry, depth),
            },
            constants::DW_TAG_array_type => self.array(at, entry, depth),
            constants::DW_TAG_structure_type
            | constants::DW_TAG_class_type
            | constants::DW_TAG_union_type => self.composite(at, entry, bytes, depth),
            constants::DW_TAG_enumeration_type => {
                let underlying = self.type_of(unit, entry, depth);
                let resolved = self.model.resolve(underlying);
                let signed = if let Type::Base { encoding, .. } = self.model.ty(resolved) {
                    matches!(encoding, Encoding::Signed | Encoding::Char { signed: true })
                } else {
                    false
                };
                Type::Enum {
                    name: self.name(unit, entry),
                    bytes: bytes.unwrap_or(4),
                    signed,
                }
            }
            constants::DW_TAG_subroutine_type => self.function_type(at, entry, depth),
            _ => Type::Unknown,
        }
    }

    /// The children of the DIE at `at` (each with its own entry), or the
    /// damage reading them.
    fn children(&self, at: At) -> Result<Vec<Entry<'a>>, gimli::Error> {
        let Some(unit) = self.unit(at.unit) else {
            return Ok(Vec::new());
        };
        let mut tree = unit.entries_tree(Some(at.offset))?;
        let root = tree.root()?;
        let mut children = root.children();
        let mut out = Vec::new();
        while let Some(child) = children.next()? {
            out.push(child.entry().clone());
        }
        Ok(out)
    }

    fn children_or_damage(&mut self, at: At) -> Vec<Entry<'a>> {
        self.children(at).unwrap_or_else(|error| {
            self.damage(
                format!("children of unit {} +{:#x}", at.unit, at.offset.0),
                &error,
            );
            Vec::new()
        })
    }

    fn array(&mut self, at: At, entry: &Entry<'a>, depth: u32) -> Type {
        let mut element = self.type_of(at.unit, entry, depth);
        let counts: Vec<Option<u64>> = self
            .children_or_damage(at)
            .iter()
            .filter(|child| child.tag() == constants::DW_TAG_subrange_type)
            .map(|child| {
                child
                    .attr_value(constants::DW_AT_count)
                    .and_then(|value| value.udata_value())
                    .or_else(|| {
                        let upper = child
                            .attr_value(constants::DW_AT_upper_bound)?
                            .udata_value()?;
                        let lower = child
                            .attr_value(constants::DW_AT_lower_bound)
                            .and_then(|value| value.udata_value())
                            .unwrap_or(0);
                        upper.checked_sub(lower)?.checked_add(1)
                    })
            })
            .collect();
        // `int a[2][3]` is an array of 2 arrays of 3: the last subrange is
        // the innermost.
        let Some((&outer, inner)) = counts.split_first() else {
            return Type::Array {
                element,
                count: None,
            };
        };
        for &count in inner.iter().rev() {
            element = self.push(Type::Array { element, count });
        }
        Type::Array {
            element,
            count: outer,
        }
    }

    fn composite(&mut self, at: At, entry: &Entry<'a>, size: Option<u64>, depth: u32) -> Type {
        let kind = match entry.tag() {
            constants::DW_TAG_class_type => CompositeKind::Class,
            constants::DW_TAG_union_type => CompositeKind::Union,
            _ => CompositeKind::Struct,
        };
        let mut fields = Vec::new();
        for child in self.children_or_damage(at) {
            let tag = child.tag();
            if tag != constants::DW_TAG_member && tag != constants::DW_TAG_inheritance {
                continue;
            }
            // Static members have no location (DWARF 4) or are variables
            // (DWARF 5).
            if child.attr_value(constants::DW_AT_external).is_some()
                || child.attr_value(constants::DW_AT_declaration).is_some()
            {
                continue;
            }
            let ty = self.type_of(at.unit, &child, depth);
            let (offset, bits) = self.member_offset(&child, ty);
            let name = if tag == constants::DW_TAG_member {
                self.name(at.unit, &child)
            } else {
                None
            };
            fields.push(Field {
                name,
                offset,
                ty,
                bits,
            });
        }
        Type::Composite(Composite {
            kind,
            name: self.name(at.unit, entry),
            size,
            fields,
        })
    }

    /// A member's byte offset and, for a bit-field, its bit offset from
    /// there and its width.
    fn member_offset(&self, member: &Entry<'a>, ty: TypeId) -> (u64, Option<(u64, u64)>) {
        let location = match member.attr_value(constants::DW_AT_data_member_location) {
            Some(AttributeValue::Exprloc(expression)) => plus_uconst(expression),
            Some(value) => value.udata_value(),
            None => None,
        };
        let width = member
            .attr_value(constants::DW_AT_bit_size)
            .and_then(|value| value.udata_value());
        let Some(width) = width else {
            return (location.unwrap_or(0), None);
        };
        if let Some(bit) = member
            .attr_value(constants::DW_AT_data_bit_offset)
            .and_then(|value| value.udata_value())
        {
            return (bit / 8, Some((bit % 8, width)));
        }
        // DWARF 2/3: `DW_AT_bit_offset` counts from the storage unit's most
        // significant bit (little-endian targets).
        let storage = member
            .attr_value(constants::DW_AT_byte_size)
            .and_then(|value| value.udata_value())
            .or_else(|| self.model.size(ty))
            .unwrap_or(0);
        let from_top = member
            .attr_value(constants::DW_AT_bit_offset)
            .and_then(|value| value.udata_value());
        let bit = from_top
            .and_then(|from_top| (storage * 8).checked_sub(from_top)?.checked_sub(width))
            .unwrap_or(0);
        (location.unwrap_or(0), Some((bit, width)))
    }

    fn function_type(&mut self, at: At, entry: &Entry<'a>, depth: u32) -> Type {
        let returns = self.type_of(at.unit, entry, depth);
        let mut parameters = Vec::new();
        let mut variadic = false;
        for child in self.children_or_damage(at) {
            match child.tag() {
                constants::DW_TAG_formal_parameter => {
                    parameters.push(self.type_of(at.unit, &child, depth));
                }
                constants::DW_TAG_unspecified_parameters => variadic = true,
                _ => {}
            }
        }
        Type::Function {
            returns,
            parameters,
            variadic,
        }
    }

    fn read_functions(&mut self, unit: usize) {
        let mut subprograms = Vec::new();
        let mut variables = Vec::new();
        {
            let Some(header) = self.unit(unit) else {
                return;
            };
            let mut cursor = header.entries();
            // The tags of the entries enclosing the current one, by depth.
            let mut enclosing: Vec<DwTag> = Vec::new();
            loop {
                match cursor.next_dfs() {
                    Ok(Some(entry)) => {
                        let depth = usize::try_from(entry.depth()).unwrap_or(0);
                        enclosing.truncate(depth);
                        if entry.tag() == constants::DW_TAG_subprogram
                            && (entry.attr_value(constants::DW_AT_low_pc).is_some()
                                || entry.attr_value(constants::DW_AT_ranges).is_some())
                        {
                            subprograms.push(entry.clone());
                        }
                        // A variable outside any function (in its unit or
                        // a namespace) at a fixed address.
                        if entry.tag() == constants::DW_TAG_variable
                            && !enclosing.iter().any(|&tag| {
                                tag == constants::DW_TAG_subprogram
                                    || tag == constants::DW_TAG_lexical_block
                                    || tag == constants::DW_TAG_inlined_subroutine
                            })
                        {
                            variables.push(entry.clone());
                        }
                        enclosing.push(entry.tag());
                    }
                    Ok(None) => break,
                    Err(error) => {
                        self.damage(format!("unit {unit}"), &error);
                        break;
                    }
                }
            }
        }
        for entry in subprograms {
            if let Some(mut function) = self.function(unit, &entry)
                && !self.model.functions.contains_key(&function.entry)
            {
                let declared = self.declared_in(unit, &entry);
                function.unit = self
                    .source_unit(declared)
                    .or_else(|| self.source_unit(unit));
                self.model.functions.insert(function.entry, function);
            }
        }
        for entry in variables {
            self.global(unit, &entry);
        }
    }

    /// The unit of the end of `entry`'s `DW_AT_abstract_origin` and
    /// `DW_AT_specification` chain (a few levels deep, as
    /// [`Self::inherited`]): `unit` without one.
    fn declared_in(&self, unit: usize, entry: &Entry<'a>) -> usize {
        let mut at = At {
            unit,
            offset: entry.offset(),
        };
        let mut entry = Cow::Borrowed(entry);
        for _ in 0..4 {
            let Some(origin) = entry
                .attr_value(constants::DW_AT_abstract_origin)
                .or_else(|| entry.attr_value(constants::DW_AT_specification))
                .and_then(|origin| self.reference(at.unit, &origin))
            else {
                break;
            };
            let Some(next) = self.entry(origin) else {
                break;
            };
            at = origin;
            entry = Cow::Owned(next);
        }
        at.unit
    }

    /// Unit `unit` as a compilation unit, added to [`DebugModel::units`] the
    /// first time: a unit whose root is a `DW_TAG_compile_unit` or
    /// `DW_TAG_skeleton_unit` with a name; else (a partial or type unit)
    /// none.
    fn source_unit(&mut self, unit: usize) -> Option<UnitId> {
        if let Some(&id) = self.sources.get(&unit) {
            return id;
        }
        let id = self.new_source_unit(unit);
        self.sources.insert(unit, id);
        id
    }

    fn new_source_unit(&mut self, unit: usize) -> Option<UnitId> {
        let header = self.unit(unit)?;
        let root = header.entry(header.header.root_offset()).ok()?;
        if root.tag() != constants::DW_TAG_compile_unit
            && root.tag() != constants::DW_TAG_skeleton_unit
        {
            return None;
        }
        let text = |value: Option<R<'a>>| value.map(|text| text.to_string_lossy().into_owned());
        let language = match root.attr_value(constants::DW_AT_language) {
            Some(AttributeValue::Language(
                constants::DW_LANG_C89
                | constants::DW_LANG_C
                | constants::DW_LANG_C99
                | constants::DW_LANG_C11
                | constants::DW_LANG_C17
                | DW_LANG_C23,
            )) => Language::C,
            Some(_) | None => Language::Other,
        };
        let source = SourceUnit {
            name: text(header.name)?,
            directory: text(header.comp_dir),
            language,
        };
        Some(self.model.push_unit(source))
    }

    /// Records `entry`, a variable outside any function, where its
    /// location is one address (`DW_OP_addr`, `DW_OP_addrx`) and it has a
    /// name.
    fn global(&mut self, unit: usize, entry: &Entry<'a>) {
        let Some(AttributeValue::Exprloc(expression)) = entry.attr_value(constants::DW_AT_location)
        else {
            return;
        };
        let address = match self.operations(unit, expression).as_deref() {
            Some(&[Operation::Address { address }]) => Some(address),
            Some(&[Operation::AddressIndex { index }]) => self
                .unit(unit)
                .and_then(|header| self.dwarf.address(header, index).ok()),
            _ => None,
        };
        let (Some(address), Some(name)) = (address, self.name(unit, entry)) else {
            return;
        };
        let ty = self.type_of(unit, entry, TYPE_DEPTH);
        self.model
            .globals
            .entry(address)
            .or_insert(Global { name, ty });
    }

    fn ranges(&mut self, unit: usize, entry: &Entry<'a>) -> Vec<Range<u64>> {
        let Some(header) = self.unit(unit) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let result = self.dwarf.die_ranges(header, entry).and_then(|mut ranges| {
            while let Some(range) = ranges.next()? {
                if range.begin < range.end {
                    out.push(range.begin..range.end);
                }
            }
            Ok(())
        });
        if let Err(error) = result {
            self.damage(
                format!("ranges of unit {unit} +{:#x}", entry.offset().0),
                &error,
            );
        }
        out
    }

    fn function(&mut self, unit: usize, entry: &Entry<'a>) -> Option<Function> {
        let ranges = self.ranges(unit, entry);
        let low = entry
            .attr_value(constants::DW_AT_entry_pc)
            .or_else(|| entry.attr_value(constants::DW_AT_low_pc))
            .and_then(|value| {
                self.dwarf
                    .attr_address(self.unit(unit)?, value)
                    .ok()
                    .flatten()
            })
            .or_else(|| ranges.first().map(|range| range.start))?;
        let frame_base = match entry.attr_value(constants::DW_AT_frame_base) {
            Some(AttributeValue::Exprloc(expression)) => self.frame_base(unit, expression),
            Some(_) | None => FrameBase::Unknown,
        };
        let returns = self.type_of(unit, entry, TYPE_DEPTH);
        let mut function = Function {
            entry: low,
            name: self.name(unit, entry),
            parameters: Vec::new(),
            returns,
            variadic: false,
            arity: None,
            locals: Vec::new(),
            unit: None,
        };
        let scope = Scope {
            unit,
            frame_base,
            ranges,
        };
        self.variables(
            &scope,
            At {
                unit,
                offset: entry.offset(),
            },
            &mut function,
        );
        Some(function)
    }

    /// The parameters and variables of a function's body, its lexical
    /// blocks included, inlined callees and nested functions not.
    fn variables(&mut self, scope: &Scope, at: At, function: &mut Function) {
        for child in self.children_or_damage(at) {
            let tag: DwTag = child.tag();
            match tag {
                constants::DW_TAG_formal_parameter => {
                    let variable = self.variable(scope, &child);
                    function.parameters.push(variable);
                }
                constants::DW_TAG_variable => {
                    let variable = self.variable(scope, &child);
                    function.locals.push(variable);
                }
                constants::DW_TAG_unspecified_parameters => function.variadic = true,
                constants::DW_TAG_lexical_block => {
                    self.variables(
                        scope,
                        At {
                            unit: scope.unit,
                            offset: child.offset(),
                        },
                        function,
                    );
                }
                _ => {}
            }
        }
    }

    fn variable(&mut self, scope: &Scope, entry: &Entry<'a>) -> Variable {
        let unit = scope.unit;
        let ty = self.type_of(unit, entry, TYPE_DEPTH);
        let name = self.name(unit, entry);
        let location = match entry.attr_value(constants::DW_AT_location) {
            Some(AttributeValue::Exprloc(expression)) => {
                let place = self.place(unit, expression, scope.frame_base);
                scope
                    .ranges
                    .iter()
                    .map(|range| Span {
                        range: range.clone(),
                        place: place.clone(),
                    })
                    .collect()
            }
            Some(value) => self.location_list(scope, entry, value),
            None => Vec::new(),
        };
        Variable { name, ty, location }
    }

    fn location_list(
        &mut self,
        scope: &Scope,
        entry: &Entry<'a>,
        value: AttributeValue<R<'a>>,
    ) -> Vec<Span> {
        let Some(header) = self.unit(scope.unit) else {
            return Vec::new();
        };
        let mut entries = Vec::new();
        let result = self.dwarf.attr_locations(header, value).and_then(|list| {
            if let Some(mut list) = list {
                while let Some(item) = list.next()? {
                    entries.push(item);
                }
            }
            Ok(())
        });
        if let Err(error) = result {
            self.damage(
                format!("locations of unit {} +{:#x}", scope.unit, entry.offset().0),
                &error,
            );
        }
        entries
            .into_iter()
            .filter(|item| item.range.begin < item.range.end)
            .map(|item| Span {
                range: item.range.begin..item.range.end,
                place: self.place(scope.unit, item.data, scope.frame_base),
            })
            .collect()
    }

    fn operations(
        &self,
        unit: usize,
        expression: Expression<R<'a>>,
    ) -> Option<Vec<Operation<R<'a>>>> {
        let encoding = self.unit(unit)?.encoding();
        let mut operations = expression.operations(encoding);
        let mut out = Vec::new();
        while let Some(operation) = operations.next().ok()? {
            out.push(operation);
            if out.len() > 8 {
                return None;
            }
        }
        Some(out)
    }

    fn frame_base(&self, unit: usize, expression: Expression<R<'a>>) -> FrameBase {
        match self.operations(unit, expression).as_deref() {
            Some([Operation::CallFrameCFA]) => FrameBase::Cfa,
            Some([Operation::Register { register }]) => {
                (self.register_name)(*register).map_or(FrameBase::Unknown, FrameBase::Register)
            }
            _ => FrameBase::Unknown,
        }
    }

    fn place(&self, unit: usize, expression: Expression<R<'a>>, frame_base: FrameBase) -> Place {
        let register = |register| (self.register_name)(register);
        match self.operations(unit, expression).as_deref() {
            Some([Operation::Register { register: r }]) => {
                register(*r).map_or(Place::Other, Place::Register)
            }
            Some([Operation::FrameOffset { offset }]) => match frame_base {
                FrameBase::Cfa => Place::Stack(*offset),
                FrameBase::Register(register) => Place::Relative {
                    register,
                    offset: *offset,
                },
                FrameBase::Unknown => Place::Other,
            },
            Some([Operation::CallFrameCFA, Operation::PlusConstant { value }]) => {
                i64::try_from(*value).map_or(Place::Other, Place::Stack)
            }
            Some(
                [
                    Operation::RegisterOffset {
                        register: r,
                        offset,
                        ..
                    },
                ],
            ) => register(*r).map_or(Place::Other, |register| Place::Relative {
                register,
                offset: *offset,
            }),
            _ => Place::Other,
        }
    }
}

struct Scope {
    unit: usize,
    frame_base: FrameBase,
    ranges: Vec<Range<u64>>,
}

fn encoding(entry: &Entry<'_>) -> Encoding {
    let Some(AttributeValue::Encoding(encoding)) = entry.attr_value(constants::DW_AT_encoding)
    else {
        return Encoding::Other;
    };
    match encoding {
        constants::DW_ATE_signed => Encoding::Signed,
        constants::DW_ATE_unsigned => Encoding::Unsigned,
        constants::DW_ATE_signed_char => Encoding::Char { signed: true },
        constants::DW_ATE_unsigned_char | constants::DW_ATE_UTF => Encoding::Char { signed: false },
        constants::DW_ATE_boolean => Encoding::Bool,
        constants::DW_ATE_float => Encoding::Float,
        _ => Encoding::Other,
    }
}

/// The constant of a `DW_OP_plus_uconst N` member location (or of a bare
/// constant).
fn plus_uconst(expression: Expression<R<'_>>) -> Option<u64> {
    let mut reader = expression.0;
    let encoding = gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version: 4,
        address_size: 8,
    };
    let operation = Operation::parse(&mut reader, encoding).ok()?;
    if let Operation::PlusConstant { value } | Operation::UnsignedConstant { value } = operation {
        Some(value)
    } else {
        None
    }
}
