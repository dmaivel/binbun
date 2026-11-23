//! The conversions of C's pointers into references and slices: the only
//! `unsafe` code of the crate. Each function states what its caller (an
//! entry point, passing on what the header's contract guarantees) must
//! uphold; everything else is safe Rust.

use std::mem::MaybeUninit;
use std::slice;

use crate::Status;

/// A decoded instruction as it sits in the caller's storage: `tag` says
/// which decoder wrote it, so storage that holds no instruction (or another
/// architecture's) is refused rather than misread.
#[repr(C)]
#[derive(Debug)]
pub struct Stored<I> {
    tag: u64,
    instruction: I,
}

/// The `len` bytes at `bytes`; empty (and `bytes` may be null) when `len`
/// is 0.
///
/// # Errors
///
/// [`Status::NullPointer`] if `bytes` is null and `len` is not 0.
///
/// # Safety
///
/// `bytes` is null or valid for reads of `len` bytes, which nothing writes
/// for `'a`.
pub unsafe fn bytes<'a>(bytes: *const u8, len: usize) -> Result<&'a [u8], Status> {
    if len == 0 {
        return Ok(&[]);
    }
    if bytes.is_null() {
        return Err(Status::NullPointer);
    }
    // SAFETY: `bytes` is not null and, by the caller's contract, readable
    // for `len` bytes that nothing writes for `'a`; a `u8` has no alignment.
    Ok(unsafe { slice::from_raw_parts(bytes, len) })
}

/// Checks that `out` can be passed to [`store`]: not null, aligned.
///
/// # Errors
///
/// [`Status::NullPointer`] if `out` is null, [`Status::BadArgument`] if it
/// is not aligned for `S`.
pub fn storage<S>(out: *mut S) -> Result<(), Status> {
    if out.is_null() {
        Err(Status::NullPointer)
    } else if out.is_aligned() {
        Ok(())
    } else {
        Err(Status::BadArgument)
    }
}

/// Writes `instruction`, tagged `tag`, into the storage at `out`, with no
/// check between the decode and the write, so that the instruction is
/// copied once.
///
/// # Safety
///
/// `out` passed [`storage`] and is valid for writes of `size_of::<S>()`
/// bytes.
#[inline]
pub unsafe fn store<S, I>(out: *mut S, tag: u64, instruction: I) {
    const {
        assert!(size_of::<Stored<I>>() <= size_of::<S>());
        assert!(align_of::<Stored<I>>() <= align_of::<S>());
    }
    // SAFETY: `out` is aligned for `S` and not null (checked by `storage`)
    // and writable for its size (caller); `Stored<I>` fits in `S` and needs
    // no more alignment (asserted above).
    unsafe { out.cast::<Stored<I>>().write(Stored { tag, instruction }) };
}

/// The instruction in the storage at `inst`, if a decode tagged `tag`
/// wrote it; `None` for a null or misaligned pointer.
///
/// # Safety
///
/// `inst` is null or points to storage of type `S` that a successful decode
/// of this library wrote (whichever decoder) and that nothing writes for
/// `'a`.
pub unsafe fn load<'a, S, I>(inst: *const S, tag: u64) -> Option<&'a I> {
    const {
        assert!(size_of::<Stored<I>>() <= size_of::<S>());
        assert!(align_of::<Stored<I>>() <= align_of::<S>());
    }
    if inst.is_null() || !inst.is_aligned() {
        return None;
    }
    let stored = inst.cast::<Stored<I>>();
    // SAFETY: `stored` is aligned and readable for `size_of::<S>()` bytes,
    // which hold `Stored<I>`; the tag is its first field (`repr(C)`), a `u64`
    // written by a decode.
    let written = unsafe { stored.cast::<u64>().read() };
    if written != tag {
        return None;
    }
    // SAFETY: the tag is this decoder's, so the decode wrote a `Stored<I>`
    // here, which nothing writes for `'a`.
    Some(unsafe { &(*stored).instruction })
}

/// The `capacity` elements at `out`, to be written; empty if `out` is null
/// or misaligned. The capacity is capped at what a slice can hold.
///
/// # Safety
///
/// `out` is null or valid for writes of `capacity` elements, which nothing
/// else reads or writes for `'a`.
pub unsafe fn out_slice<'a, T>(out: *mut T, capacity: usize) -> &'a mut [MaybeUninit<T>] {
    if out.is_null() || !out.is_aligned() || capacity == 0 {
        return &mut [];
    }
    let capacity = capacity.min(isize::MAX.unsigned_abs() / size_of::<T>().max(1));
    // SAFETY: `out` is aligned, not null and, by the caller's contract,
    // writable and unaliased for `capacity` elements (no more than a slice
    // can span); `MaybeUninit` needs no initialised contents.
    unsafe { slice::from_raw_parts_mut(out.cast::<MaybeUninit<T>>(), capacity) }
}

/// Writes `value` to `out`, which needs no alignment; nothing for a null
/// pointer.
///
/// # Safety
///
/// `out` is null or valid for writes of a `T`.
pub unsafe fn write<T>(out: *mut T, value: T) {
    if !out.is_null() {
        // SAFETY: not null and writable (caller); unaligned writes are
        // allowed.
        unsafe { out.write_unaligned(value) };
    }
}

/// The caller's `T` at `value`, to read and update; `None` if null or
/// misaligned.
///
/// # Safety
///
/// `value` is null or points to an initialised `T` that nothing else reads
/// or writes for `'a`; `T` is a plain C struct, whose every bit pattern is
/// valid.
pub unsafe fn borrow_mut<'a, T>(value: *mut T) -> Option<&'a mut T> {
    if value.is_null() || !value.is_aligned() {
        return None;
    }
    // SAFETY: aligned, not null, initialised and unaliased (caller).
    Some(unsafe { &mut *value })
}

/// The caller's `T` at `value`, to read; `None` if null or misaligned.
///
/// # Safety
///
/// `value` is null or points to an initialised `T` that nothing writes for
/// `'a`; `T` is a plain C struct, whose every bit pattern is valid.
pub unsafe fn borrow<'a, T>(value: *const T) -> Option<&'a T> {
    if value.is_null() || !value.is_aligned() {
        return None;
    }
    // SAFETY: aligned, not null, initialised and not written (caller).
    Some(unsafe { &*value })
}
