// automatically generated by the FlatBuffers compiler, do not modify
// @generated
extern crate alloc;
extern crate flatbuffers;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::mem;

use self::flatbuffers::{EndianScalar, Follow};
use super::*;
pub enum GuestErrorOffset {}
#[derive(Copy, Clone, PartialEq)]

pub struct GuestError<'a> {
    pub _tab: flatbuffers::Table<'a>,
}

impl<'a> flatbuffers::Follow<'a> for GuestError<'a> {
    type Inner = GuestError<'a>;
    #[inline]
    unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
        unsafe {
            Self {
                _tab: flatbuffers::Table::new(buf, loc),
            }
        }
    }
}

impl<'a> GuestError<'a> {
    pub const VT_CODE: flatbuffers::VOffsetT = 4;
    pub const VT_MESSAGE: flatbuffers::VOffsetT = 6;

    #[inline]
    pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
        GuestError { _tab: table }
    }
    #[allow(unused_mut)]
    pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr, A: flatbuffers::Allocator + 'bldr>(
        _fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
        args: &'args GuestErrorArgs<'args>,
    ) -> flatbuffers::WIPOffset<GuestError<'bldr>> {
        let mut builder = GuestErrorBuilder::new(_fbb);
        builder.add_code(args.code);
        if let Some(x) = args.message {
            builder.add_message(x);
        }
        builder.finish()
    }

    #[inline]
    pub fn code(&self) -> ErrorCode {
        // Safety:
        // Created from valid Table for this object
        // which contains a valid value in this slot
        unsafe {
            self._tab
                .get::<ErrorCode>(GuestError::VT_CODE, Some(ErrorCode::NoError))
                .unwrap()
        }
    }
    #[inline]
    pub fn message(&self) -> Option<&'a str> {
        // Safety:
        // Created from valid Table for this object
        // which contains a valid value in this slot
        unsafe {
            self._tab
                .get::<flatbuffers::ForwardsUOffset<&str>>(GuestError::VT_MESSAGE, None)
        }
    }
}

impl flatbuffers::Verifiable for GuestError<'_> {
    #[inline]
    fn run_verifier(
        v: &mut flatbuffers::Verifier,
        pos: usize,
    ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
        use self::flatbuffers::Verifiable;
        v.visit_table(pos)?
            .visit_field::<ErrorCode>("code", Self::VT_CODE, false)?
            .visit_field::<flatbuffers::ForwardsUOffset<&str>>("message", Self::VT_MESSAGE, false)?
            .finish();
        Ok(())
    }
}
pub struct GuestErrorArgs<'a> {
    pub code: ErrorCode,
    pub message: Option<flatbuffers::WIPOffset<&'a str>>,
}
impl<'a> Default for GuestErrorArgs<'a> {
    #[inline]
    fn default() -> Self {
        GuestErrorArgs {
            code: ErrorCode::NoError,
            message: None,
        }
    }
}

pub struct GuestErrorBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
    fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
    start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
}
impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> GuestErrorBuilder<'a, 'b, A> {
    #[inline]
    pub fn add_code(&mut self, code: ErrorCode) {
        self.fbb_
            .push_slot::<ErrorCode>(GuestError::VT_CODE, code, ErrorCode::NoError);
    }
    #[inline]
    pub fn add_message(&mut self, message: flatbuffers::WIPOffset<&'b str>) {
        self.fbb_
            .push_slot_always::<flatbuffers::WIPOffset<_>>(GuestError::VT_MESSAGE, message);
    }
    #[inline]
    pub fn new(
        _fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
    ) -> GuestErrorBuilder<'a, 'b, A> {
        let start = _fbb.start_table();
        GuestErrorBuilder {
            fbb_: _fbb,
            start_: start,
        }
    }
    #[inline]
    pub fn finish(self) -> flatbuffers::WIPOffset<GuestError<'a>> {
        let o = self.fbb_.end_table(self.start_);
        flatbuffers::WIPOffset::new(o.value())
    }
}

impl core::fmt::Debug for GuestError<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut ds = f.debug_struct("GuestError");
        ds.field("code", &self.code());
        ds.field("message", &self.message());
        ds.finish()
    }
}
#[inline]
/// Verifies that a buffer of bytes contains a `GuestError`
/// and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_guest_error_unchecked`.
pub fn root_as_guest_error(buf: &[u8]) -> Result<GuestError, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::root::<GuestError>(buf)
}
#[inline]
/// Verifies that a buffer of bytes contains a size prefixed
/// `GuestError` and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `size_prefixed_root_as_guest_error_unchecked`.
pub fn size_prefixed_root_as_guest_error(
    buf: &[u8],
) -> Result<GuestError, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::size_prefixed_root::<GuestError>(buf)
}
#[inline]
/// Verifies, with the given options, that a buffer of bytes
/// contains a `GuestError` and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_guest_error_unchecked`.
pub fn root_as_guest_error_with_opts<'b, 'o>(
    opts: &'o flatbuffers::VerifierOptions,
    buf: &'b [u8],
) -> Result<GuestError<'b>, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::root_with_opts::<GuestError<'b>>(opts, buf)
}
#[inline]
/// Verifies, with the given verifier options, that a buffer of
/// bytes contains a size prefixed `GuestError` and returns
/// it. Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_guest_error_unchecked`.
pub fn size_prefixed_root_as_guest_error_with_opts<'b, 'o>(
    opts: &'o flatbuffers::VerifierOptions,
    buf: &'b [u8],
) -> Result<GuestError<'b>, flatbuffers::InvalidFlatbuffer> {
    flatbuffers::size_prefixed_root_with_opts::<GuestError<'b>>(opts, buf)
}
#[inline]
/// Assumes, without verification, that a buffer of bytes contains a GuestError and returns it.
/// # Safety
/// Callers must trust the given bytes do indeed contain a valid `GuestError`.
pub unsafe fn root_as_guest_error_unchecked(buf: &[u8]) -> GuestError {
    unsafe { flatbuffers::root_unchecked::<GuestError>(buf) }
}
#[inline]
/// Assumes, without verification, that a buffer of bytes contains a size prefixed GuestError and returns it.
/// # Safety
/// Callers must trust the given bytes do indeed contain a valid size prefixed `GuestError`.
pub unsafe fn size_prefixed_root_as_guest_error_unchecked(buf: &[u8]) -> GuestError {
    unsafe { flatbuffers::size_prefixed_root_unchecked::<GuestError>(buf) }
}
#[inline]
pub fn finish_guest_error_buffer<'a, 'b, A: flatbuffers::Allocator + 'a>(
    fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
    root: flatbuffers::WIPOffset<GuestError<'a>>,
) {
    fbb.finish(root, None);
}

#[inline]
pub fn finish_size_prefixed_guest_error_buffer<'a, 'b, A: flatbuffers::Allocator + 'a>(
    fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
    root: flatbuffers::WIPOffset<GuestError<'a>>,
) {
    fbb.finish_size_prefixed(root, None);
}
