#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The L1 interpreter on hand-built functions: block parameters as parallel
//! copies, undefined conditions, memory through the machine, partial
//! register writes, a value less itself.

use std::collections::BTreeMap;

use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{Fault, Machine, Value};
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_semantics::{Declarations, RegisterInfo};
use binbun_ssa::interpret::{Outcome, run};
use binbun_ssa::ir::{
    self, Block, BlockId, Definition, Function, Inst, InstId, Op, State, Target, Terminator, Type,
    ValueInfo,
};

/// Registers `a` and `b` (32 bits) and `c` (16 bits).
const DECLARATIONS: Declarations = Declarations {
    registers: &[
        RegisterInfo {
            name: "a",
            width: 32,
        },
        RegisterInfo {
            name: "b",
            width: 32,
        },
        RegisterInfo {
            name: "c",
            width: 16,
        },
    ],
    intrinsics: &[],
    sites: &[],
};

/// Where the test memory ends: accesses at or past it fault.
const LIMIT: u64 = 0x1000;

const FUEL: u64 = 1000;

/// A memory of bytes below [`LIMIT`] (0 where never written).
#[derive(Default)]
struct Memory {
    bytes: BTreeMap<u64, u8>,
}

impl Machine for Memory {
    fn read(&mut self, _: RegisterId) -> Value {
        unreachable!("L1 holds registers in values")
    }

    fn write(&mut self, _: RegisterId, _: Value) {
        unreachable!("L1 holds registers in values")
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        if address + u64::from(bytes) > LIMIT {
            return Err(Fault {
                address,
                write: false,
            });
        }
        let mut buffer = [0u8; 8];
        for (offset, byte) in (0..u64::from(bytes)).zip(&mut buffer) {
            *byte = self.bytes.get(&(address + offset)).copied().unwrap_or(0);
        }
        Ok(defined(bytes * 8, u64::from_le_bytes(buffer)))
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        let bytes = u64::from(value.width() / 8);
        if address + bytes > LIMIT {
            return Err(Fault {
                address,
                write: true,
            });
        }
        for (offset, byte) in (0..bytes).zip(value.bits.low_u64().to_le_bytes()) {
            self.bytes.insert(address + offset, byte);
        }
        Ok(())
    }
}

fn defined(width: u16, value: u64) -> Value {
    Value::defined(Bits::from_u64(width, value))
}

/// A value whose `undefined` bits are undefined (`bits` must be 0 there).
fn partial(width: u16, bits: u64, undefined: u64) -> Value {
    Value {
        bits: Bits::from_u64(width, bits),
        undefined: Bits::from_u64(width, undefined),
    }
}

/// The parameters of a block holding the whole state: the registers, then
/// the memory.
const STATE: [Type; 4] = [Type::Bits(32), Type::Bits(32), Type::Bits(16), Type::Memory];

/// Builds a function by hand.
struct Builder {
    function: Function,
}

impl Builder {
    /// A function entered at `entry`, with its entry block (block 0) and its
    /// parameters.
    fn new(entry: u64) -> (Self, [ir::Value; 4]) {
        let mut builder = Self {
            function: Function {
                entry,
                ..Function::default()
            },
        };
        let (_, parameters) = builder.block(entry);
        (builder, parameters)
    }

    fn value(&mut self, ty: Type, definition: Definition) -> ir::Value {
        let id = ir::Value(u32::try_from(self.function.values.len()).unwrap());
        self.function.values.push(ValueInfo { ty, definition });
        id
    }

    /// A block at `address` with the whole state as parameters.
    fn block(&mut self, address: u64) -> (BlockId, [ir::Value; 4]) {
        let block = BlockId(u32::try_from(self.function.blocks.len()).unwrap());
        let parameters: Vec<ir::Value> = (0..)
            .zip(STATE)
            .map(|(index, ty)| self.value(ty, Definition::Parameter { block, index }))
            .collect();
        self.function.blocks.push(Block {
            address,
            end: address,
            parameters: parameters.clone(),
            insts: Vec::new(),
            terminator: Terminator::Open,
        });
        (block, parameters.try_into().unwrap())
    }

    /// Appends `op` with one result of type `ty` to `block`.
    fn op(&mut self, block: BlockId, op: Op, ty: Type) -> ir::Value {
        let inst = InstId(u32::try_from(self.function.insts.len()).unwrap());
        let result = self.value(ty, Definition::Result { inst, index: 0 });
        let address = self.function.blocks[block.0 as usize].address;
        self.function.insts.push(Inst {
            op,
            results: vec![result],
            address,
        });
        self.function.blocks[block.0 as usize].insts.push(inst);
        result
    }

    fn constant(&mut self, block: BlockId, width: u16, value: u64) -> ir::Value {
        self.op(
            block,
            Op::Const(Bits::from_u64(width, value)),
            Type::Bits(width),
        )
    }

    fn terminate(&mut self, block: BlockId, terminator: Terminator) {
        self.function.blocks[block.0 as usize].terminator = terminator;
    }

    /// Ends `block` with a return to `address` in `state`.
    fn ret(&mut self, block: BlockId, address: u64, state: [ir::Value; 4]) {
        let address = self.constant(block, 64, address);
        let [a, b, c, memory] = state;
        self.terminate(
            block,
            Terminator::Return {
                address,
                state: State {
                    registers: vec![a, b, c],
                    memory,
                },
            },
        );
    }
}

fn jump(block: BlockId, arguments: [ir::Value; 4]) -> Target {
    Target {
        block,
        arguments: arguments.to_vec(),
    }
}

fn exit(returned: bool, address: u64, registers: &[Value; 3]) -> Outcome {
    Outcome::Exit {
        returned,
        address,
        registers: registers.to_vec(),
    }
}

/// Swaps `a` and `b` `c - 1` times: `loop(x, y, n): n -= 1; if n == 0 goto
/// done(x, y, n) else goto loop(y, x, n)`, then returns to 0x2000.
fn swap_loop() -> Function {
    let (mut builder, entry) = Builder::new(0x100);
    let (looping, [x, y, n, memory]) = builder.block(0x100);
    let (done, done_state) = builder.block(0x110);
    builder.terminate(BlockId(0), Terminator::Jump(jump(looping, entry)));
    let one = builder.constant(looping, 16, 1);
    let zero = builder.constant(looping, 16, 0);
    let next = builder.op(looping, Op::Binary(Binary::Sub, n, one), Type::Bits(16));
    let finished = builder.op(looping, Op::Binary(Binary::Eq, next, zero), Type::Bits(1));
    builder.terminate(
        looping,
        Terminator::Branch {
            condition: finished,
            then: jump(done, [x, y, next, memory]),
            otherwise: jump(looping, [y, x, next, memory]),
        },
    );
    builder.ret(done, 0x2000, done_state);
    builder.function
}

#[test]
fn block_parameters_are_bound_in_parallel() {
    let function = swap_loop();
    let registers = [defined(32, 1), defined(32, 2), defined(16, 4)];
    // Three swaps: one copy at a time would give (2, 2).
    assert_eq!(
        run(
            &function,
            &DECLARATIONS,
            &registers,
            &mut Memory::default(),
            FUEL
        ),
        exit(
            true,
            0x2000,
            &[defined(32, 2), defined(32, 1), defined(16, 0)]
        )
    );
}

#[test]
fn fuel_counts_blocks_entered() {
    let function = swap_loop();
    let registers = [defined(32, 1), defined(32, 2), defined(16, 4)];
    let mut memory = Memory::default();
    // The entry block, the loop four times, the exit.
    assert!(matches!(
        run(&function, &DECLARATIONS, &registers, &mut memory, 6),
        Outcome::Exit { .. }
    ));
    assert_eq!(
        run(&function, &DECLARATIONS, &registers, &mut memory, 5),
        Outcome::OutOfFuel
    );
}

#[test]
fn branches_need_a_defined_condition() {
    // Branches on bit 0 of `a`: returns to 0x2000 if set, else to 0x3000.
    let (mut builder, entry) = Builder::new(0x100);
    let (test, state) = builder.block(0x100);
    let (set, set_state) = builder.block(0x110);
    let (clear, clear_state) = builder.block(0x120);
    builder.terminate(BlockId(0), Terminator::Jump(jump(test, entry)));
    let bit = builder.op(
        test,
        Op::Extract {
            value: state[0],
            offset: 0,
            width: 1,
        },
        Type::Bits(1),
    );
    builder.terminate(
        test,
        Terminator::Branch {
            condition: bit,
            then: jump(set, state),
            otherwise: jump(clear, state),
        },
    );
    builder.ret(set, 0x2000, set_state);
    builder.ret(clear, 0x3000, clear_state);
    let function = builder.function;
    let mut memory = Memory::default();
    let others = [defined(32, 0), defined(16, 0)];
    let mut branch = |a: Value| {
        run(
            &function,
            &DECLARATIONS,
            &[a, others[0], others[1]],
            &mut memory,
            FUEL,
        )
    };

    // Only bit 0 defined: enough, and the undefined bits are passed on.
    let odd = partial(32, 1, 0xffff_fffe);
    assert_eq!(
        branch(odd),
        exit(true, 0x2000, &[odd, others[0], others[1]])
    );
    let even = partial(32, 0, 0xffff_fffe);
    assert_eq!(
        branch(even),
        exit(true, 0x3000, &[even, others[0], others[1]])
    );
    // Bit 0 undefined, every other bit defined.
    assert_eq!(branch(partial(32, 6, 1)), Outcome::Undetermined);
}

#[test]
fn loads_see_stores_through_the_machine() {
    // Stores `b` at `a`, then loads 4 bytes at `a` into `a` and 2 bytes at
    // `a + 1` into `c`.
    let (mut builder, entry) = Builder::new(0x100);
    let (body, [a, b, _, memory]) = builder.block(0x100);
    builder.terminate(BlockId(0), Terminator::Jump(jump(body, entry)));
    let stored = builder.op(
        body,
        Op::Store {
            memory,
            address: a,
            value: b,
            atomic: None,
        },
        Type::Memory,
    );
    let whole = builder.op(
        body,
        Op::Load {
            memory: stored,
            address: a,
            bytes: 4,
            atomic: None,
        },
        Type::Bits(32),
    );
    let one = builder.constant(body, 32, 1);
    let next = builder.op(body, Op::Binary(Binary::Add, a, one), Type::Bits(32));
    let middle = builder.op(
        body,
        Op::Load {
            memory: stored,
            address: next,
            bytes: 2,
            atomic: None,
        },
        Type::Bits(16),
    );
    builder.ret(body, 0x2000, [whole, b, middle, stored]);
    let function = builder.function;
    let value = defined(32, 0x1122_3344);
    let run_at = |address: Value, memory: &mut Memory| {
        run(
            &function,
            &DECLARATIONS,
            &[address, value, defined(16, 0)],
            memory,
            FUEL,
        )
    };

    let mut memory = Memory::default();
    memory
        .bytes
        .extend((0x100..0x108).map(|address| (address, 0xff)));
    assert_eq!(
        run_at(defined(32, 0x100), &mut memory),
        exit(true, 0x2000, &[value, value, defined(16, 0x2233)])
    );
    let written: Vec<u8> = (0x100..0x105)
        .map(|address| memory.bytes[&address])
        .collect();
    assert_eq!(written, [0x44, 0x33, 0x22, 0x11, 0xff]);

    let mut memory = Memory::default();
    assert_eq!(
        run_at(defined(32, 0x2000), &mut memory),
        Outcome::Fault(Fault {
            address: 0x2000,
            write: true
        })
    );
    assert_eq!(
        run_at(partial(32, 0x100, 0x1_0000), &mut memory),
        Outcome::Undetermined
    );
    assert!(memory.bytes.is_empty());
}

#[test]
fn partial_register_writes_keep_the_other_bits() {
    // `c`'s low byte := `a`'s low byte (x86 `mov cl, al`), then leaves to
    // 0x3000.
    let (mut builder, entry) = Builder::new(0x100);
    let (body, [a, b, c, memory]) = builder.block(0x100);
    builder.terminate(BlockId(0), Terminator::Jump(jump(body, entry)));
    let low = builder.op(
        body,
        Op::Extract {
            value: a,
            offset: 0,
            width: 8,
        },
        Type::Bits(8),
    );
    let high = builder.op(
        body,
        Op::Extract {
            value: c,
            offset: 8,
            width: 8,
        },
        Type::Bits(8),
    );
    let merged = builder.op(body, Op::Concat { high, low }, Type::Bits(16));
    let address = builder.constant(body, 64, 0x3000);
    builder.terminate(
        body,
        Terminator::Leave {
            address,
            state: State {
                registers: vec![a, b, merged],
                memory,
            },
            returns: true,
        },
    );
    let function = builder.function;

    // The bits that end up in `c` are defined; the others are not.
    let a = partial(32, 0xab, 0xffff_ff00);
    let b = defined(32, 7);
    let c = partial(16, 0xcd00, 0x00ff);
    assert_eq!(
        run(
            &function,
            &DECLARATIONS,
            &[a, b, c],
            &mut Memory::default(),
            FUEL
        ),
        exit(false, 0x3000, &[a, b, defined(16, 0xcdab)])
    );
}

#[test]
fn a_value_xor_or_less_itself_is_zero_whatever_its_bits() {
    // `c := lo(a) ^ lo(a)` (x86 `xor r9d, r9d`: two extractions of one
    // register), `b := b - b`, `a := (lo(a) ^ hi(a)) : c`, then a return.
    let (mut builder, entry) = Builder::new(0x100);
    let (body, [a, b, _, memory]) = builder.block(0x100);
    builder.terminate(BlockId(0), Terminator::Jump(jump(body, entry)));
    let extract = |builder: &mut Builder, offset| {
        builder.op(
            body,
            Op::Extract {
                value: a,
                offset,
                width: 16,
            },
            Type::Bits(16),
        )
    };
    let (low, again, high) = (
        extract(&mut builder, 0),
        extract(&mut builder, 0),
        extract(&mut builder, 16),
    );
    let zero = builder.op(body, Op::Binary(Binary::Xor, low, again), Type::Bits(16));
    let difference = builder.op(body, Op::Binary(Binary::Sub, b, b), Type::Bits(32));
    let mixed = builder.op(body, Op::Binary(Binary::Xor, low, high), Type::Bits(16));
    let merged = builder.op(
        body,
        Op::Concat {
            high: mixed,
            low: zero,
        },
        Type::Bits(32),
    );
    // And of a value with itself is the value: as undefined as it.
    let same = builder.op(body, Op::Binary(Binary::And, b, b), Type::Bits(32));
    let both = builder.op(
        body,
        Op::Extract {
            value: same,
            offset: 0,
            width: 16,
        },
        Type::Bits(16),
    );
    let low_c = builder.op(body, Op::Binary(Binary::Or, both, zero), Type::Bits(16));
    builder.ret(body, 0x2000, [merged, difference, low_c, memory]);
    let function = builder.function;

    let undefined = [Value::unknown(32), Value::unknown(32), Value::unknown(16)];
    assert_eq!(
        run(
            &function,
            &DECLARATIONS,
            &undefined,
            &mut Memory::default(),
            FUEL
        ),
        exit(
            true,
            0x2000,
            &[
                partial(32, 0, 0xffff_0000),
                defined(32, 0),
                Value::unknown(16)
            ]
        )
    );
    // Defined bits give what the operations give.
    let registers = [defined(32, 0x1234_5678), defined(32, 9), defined(16, 0)];
    assert_eq!(
        run(
            &function,
            &DECLARATIONS,
            &registers,
            &mut Memory::default(),
            FUEL
        ),
        exit(
            true,
            0x2000,
            &[defined(32, 0x444c_0000), defined(32, 0), defined(16, 9)]
        )
    );
}
