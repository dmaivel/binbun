//! Structs that are C++ classes ([`super::super::classes`]): which class
//! each struct is claimed to be, the nearest common primary base of its
//! claims ([`Classes::join`]); a class is one struct (structs claimed by
//! one class unite); a class's struct is named by the class, its first
//! field `vptr`, and the struct that field points to (the class's
//! virtual table) `<class>_vtbl`, its fields by the slots' methods. A
//! declared identity (debug information's type) outranks the class: such
//! a struct prints as its declared type, and the class names nothing.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{Field, FieldType, Member, StructId, Structs};
use crate::typing::classes::Classes;

impl Structs {
    /// Takes `classes` as the program's C++ classes (before any function
    /// adds its structs).
    pub fn set_classes(&mut self, classes: Classes) {
        self.classes = classes;
    }

    /// The program's C++ classes.
    pub const fn classes(&self) -> &Classes {
        &self.classes
    }

    /// Records that struct `id` is `class` (`None`: claimed by classes
    /// with no common base): its claim becomes the join of its claims,
    /// and a struct already the same class is united with it (`work`).
    pub(super) fn claim(
        &mut self,
        id: StructId,
        class: Option<usize>,
        work: &mut Vec<(StructId, StructId)>,
    ) {
        let id = self.find(id);
        let known = self.claims.get(&id).copied();
        let joined = match known {
            None => class,
            Some(known) => known.zip(class).and_then(|(a, b)| self.classes.join(a, b)),
        };
        if known.flatten().is_some() && class.is_some() && joined.is_none() {
            self.conflicts += 1;
        }
        self.claims.insert(id, joined);
        let Some(joined) = joined else {
            return;
        };
        match self.by_class.get(&joined).map(|&other| self.find(other)) {
            Some(other) if other != id && self.class_of(other) == Some(joined) => {
                work.push((other, id));
            }
            _ => {
                self.by_class.insert(joined, id);
            }
        }
    }

    /// Struct `lose`, united into `keep`, gives its claim to `keep` (and
    /// makes it a virtual table if it was one).
    pub(super) fn carry(
        &mut self,
        keep: StructId,
        lose: StructId,
        work: &mut Vec<(StructId, StructId)>,
    ) {
        if self.tables.remove(&lose) {
            self.tables.insert(keep);
        }
        if let Some(lost) = self.claims.remove(&lose) {
            self.claim(keep, lost, work);
        }
    }

    /// Whether structs `a` and `b` may be one as classes: two virtual
    /// tables may (a table's slots are all one width; a function shows
    /// the slots it calls); else `None` where neither is claimed by a
    /// class (the size rule then decides); else whether their classes
    /// have a common primary base (one claimed and one not: yes). Their
    /// overlapping fields must still agree.
    pub(super) fn classes_agree(&self, a: StructId, b: StructId) -> Option<bool> {
        if self.tables.contains(&self.find(a)) && self.tables.contains(&self.find(b)) {
            return Some(true);
        }
        match (self.class_of(a), self.class_of(b)) {
            (None, None) => None,
            (Some(x), Some(y)) => Some(self.classes.join(x, y).is_some()),
            (Some(_), None) | (None, Some(_)) => Some(true),
        }
    }

    /// The class struct `id` is, if one: the struct its class is (not one
    /// of two the class's claims could not unite).
    pub fn class_of(&self, id: StructId) -> Option<usize> {
        let id = self.find(id);
        let class = self.claims.get(&id).copied().flatten()?;
        let struct_ = self.by_class.get(&class).map(|&other| self.find(other))?;
        (struct_ == id).then_some(class)
    }

    /// The class whose struct's first field points to struct `id` (its
    /// virtual table), if one.
    pub fn vtable_of(&self, id: StructId) -> Option<usize> {
        let id = self.find(id);
        self.by_class.iter().find_map(|(&class, &struct_)| {
            let layout = self.layouts.get(&self.find(struct_))?;
            let FieldType::Struct(target) = layout.fields.get(&0)?.ty else {
                return None;
            };
            (self.find(target) == id && self.class_of(struct_) == Some(class)).then_some(class)
        })
    }

    /// Struct `id`'s name as a class's (its identifier) or a class's
    /// virtual table's (`<identifier>_vtbl`), if it is one and has no
    /// declared identity.
    pub(super) fn class_name(&self, id: StructId) -> Option<String> {
        if self.identities.contains_key(&self.find(id)) {
            return None;
        }
        if let Some(class) = self.class_of(id) {
            return self.classes.identifier(class).map(String::from);
        }
        let class = self.vtable_of(id)?;
        Some(format!("{}_vtbl", self.classes.identifier(class)?))
    }

    /// The name of `field` at `offset` of struct `id` (after `members`),
    /// where its class names it: a class's first field `vptr`; a virtual
    /// table's slot by its method, unless an earlier field took the name.
    pub(super) fn member_name(
        &self,
        id: StructId,
        offset: u64,
        field: &Field,
        members: &[Member],
    ) -> Option<String> {
        if offset == 0 && self.class_of(id).is_some() {
            return Some(String::from("vptr"));
        }
        let class = self.vtable_of(id)?;
        let bytes = field.bytes();
        if bytes == 0 || !offset.is_multiple_of(bytes) {
            return None;
        }
        let name = self.classes.slot(class, offset / bytes)?;
        members
            .iter()
            .all(|member| member.name.as_deref() != Some(name))
            .then(|| String::from(name))
    }

    /// How many structs are named by a class (classes and their virtual
    /// tables; not those with a declared identity).
    pub fn classed(&self) -> usize {
        self.layouts
            .keys()
            .filter(|&&id| self.class_name(id).is_some())
            .count()
    }
}
