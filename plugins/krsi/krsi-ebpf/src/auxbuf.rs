// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use krsi_common::{EventHeader, EventType};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Parameter maximum length. Since [MAX_EVENT_LEN](crate::MAX_EVENT_LEN) must be a power of 2, this
/// can be used as a mask to check that the accesses to the auxiliary map are always in bound and
/// please, in this way, the verifier.
const MAX_PARAM_VALUE_LEN: usize = crate::MAX_EVENT_LEN - 1;

/// Auxiliary buffer length. It must be able to contain an event of
/// [MAX_EVENT_LEN](crate::MAX_EVENT_LEN), but it is set to its double in order to please the
/// verifier.
const AUXILIARY_BUFFER_LEN: usize = crate::MAX_EVENT_LEN * 2;

pub struct AuxiliaryBuffer {
    /// Raw space to save our variable-size event.
    data: [u8; AUXILIARY_BUFFER_LEN],
    /// Position of the first empty slot into the values array of the event.
    values_pos: u64,
    /// Position of the first empty slot into the lengths array of the event.
    lengths_pos: u8,
    /// Event type we want to send to userspace.
    event_type: u16,
}

impl AuxiliaryBuffer {
    /// Return a [Writer] instance associated with the current buffer.
    pub fn writer(&mut self) -> Writer {
        Writer { auxbuf: self }
    }

    /// Return a slice to the underlying data.
    pub fn as_bytes(&self) -> Result<&[u8], i64> {
        // Notice: `event_header_mut()` can never return an error (see
        // `AuxiliaryBuffer::event_header()` for more details).
        let len = self.event_header()?.len.get() as usize;
        if len > self.data.len() {
            return Err(1);
        }
        Ok(&self.data[..len])
    }

    /// Return an immutable reference to the event header.
    ///
    /// Notice: this call actually cannot return an error, but it internally uses
    /// [FromBytes::ref_from_bytes] which can returns an error, and sadly tqhere is no other
    /// conversion helper performing this infallible conversion in an unchecked way.
    fn event_header(&self) -> Result<&EventHeader, i64> {
        EventHeader::ref_from_bytes(&self.data[..size_of::<EventHeader>()]).map_err(|_| 1)
    }

    /// Returns a mutable reference to the event header.
    ///
    /// Notice: this call actually cannot return an error, but it internally uses
    /// [FromBytes::mut_from_bytes] which can returns an error, and sadly there is no other
    /// conversion helper performing this infallible conversion in an unchecked way.
    pub fn event_header_mut(&mut self) -> Result<&mut EventHeader, i64> {
        EventHeader::mut_from_bytes(&mut self.data[..size_of::<EventHeader>()]).map_err(|_| 1)
    }
}

/// Utility allowing to push data on an auxiliary buffer.
pub struct Writer<'a> {
    auxbuf: &'a mut AuxiliaryBuffer,
}

impl<'a> Writer<'a> {
    pub fn preload_event_header(
        &mut self,
        ts: u64,
        tgid_pid: u64,
        event_type: EventType,
        nparams: u32,
    ) {
        // Notice: `event_header_mut()` can never return an error (see
        // `AuxiliaryBuffer::event_header_mut() for more details).
        let Ok(evt_hdr) = self.auxbuf.event_header_mut() else {
            return;
        };
        evt_hdr.ts = ts.into();
        evt_hdr.tgid_pid = tgid_pid.into();
        evt_hdr.evt_type = (event_type as u16).into();
        evt_hdr.nparams = nparams.into();
        self.auxbuf.values_pos =
            (size_of::<EventHeader>() + (nparams as usize) * size_of::<u16>()) as u64;
        self.auxbuf.lengths_pos = size_of::<EventHeader>() as u8;
        self.auxbuf.event_type = (event_type as u16).into();
    }

    pub fn finalize_event_header(&mut self) {
        let payload_pos = self.auxbuf.values_pos as u32;
        // Notice: `event_header_mut()` can never return an error (see
        // `AuxiliaryBuffer::event_header_mut() for more details).
        let Ok(evt_hdr) = self.auxbuf.event_header_mut() else {
            return;
        };
        evt_hdr.len = payload_pos.into();
    }

    pub fn skip_param(&mut self, len: u16) {
        self.auxbuf.values_pos += len as u64;
        self.auxbuf.lengths_pos = self.auxbuf.lengths_pos + size_of::<u16>() as u8;
    }

    pub fn store_param<T: IntoBytes + Immutable>(&mut self, param: T) -> Result<(), i64> {
        self.write_value(param)?;
        self.write_len(size_of::<T>() as u16)
    }

    fn write_value<T: IntoBytes + Immutable>(&mut self, value: T) -> Result<(), i64> {
        let lower_offset = Self::data_safe_access(self.auxbuf.values_pos);
        let mut data = &mut self.auxbuf.data[lower_offset..];
        write(&mut data, value)?;
        self.auxbuf.values_pos += size_of::<T>() as u64;
        Ok(())
    }

    // Helper used to please the verifier during reading operations like `bpf_probe_read_str()`.
    fn data_safe_access(x: u64) -> usize {
        (x & MAX_PARAM_VALUE_LEN as u64) as usize
    }

    fn write_len(&mut self, value: u16) -> Result<(), i64> {
        let lower_offset = Self::data_safe_access(self.auxbuf.lengths_pos as u64);
        let mut data = &mut self.auxbuf.data[lower_offset..];
        write(&mut data, value)?;
        self.auxbuf.lengths_pos += size_of::<u16>() as u8;
        Ok(())
    }

    /// Store an empty parameter.
    pub fn store_empty_param(&mut self) -> Result<(), i64> {
        self.write_len(0)
    }

    /// Provide a generic way to write a parameter whose size is not known at compile time.
    ///
    /// The user must provide the maximal expected parameter length (`max_len_to_read`) and decides
    /// (by setting `force_max_len` accordingly) if the use case can use an eventually smaller
    /// amount of bytes (in case the underlying buffer doesn't have enough space to accommodate
    /// `max_len_to_read` bytes of data).
    ///
    /// After reserving the requested amount of bytes (or less, if the amount of free space is less
    /// than the requested one and `force_max_len` is set to `false`), the provided `write_fn` is
    /// executed, receiving a [ParamWriter] allowing to write chunks of data on the reserved buffer.
    /// `write_fn` must return the amount of written bytes or an error, to abort the operation. The
    /// operation can still fail, after running `write_fn`, if the implementation is not able to
    /// write the returned amount of written bytes in the auxiliary buffer's lengths array.
    pub fn store_var_len_param<F>(
        &mut self,
        max_len_to_read: u16,
        force_max_len: bool,
        write_fn: F,
    ) -> Result<u16, i64>
    where
        F: FnOnce(ParamWriter) -> Result<u16, i64>,
    {
        let (lower_offset, upper_offset) = self.values_offsets(max_len_to_read, force_max_len)?;
        let param_writer = ParamWriter {
            data: &mut self.auxbuf.data[lower_offset..upper_offset],
        };
        let written_bytes = write_fn(param_writer)?;
        self.auxbuf.values_pos += written_bytes as u64;
        self.write_len(written_bytes)?;
        Ok(written_bytes)
    }

    fn values_offsets(
        &mut self,
        max_len_to_read: u16,
        force_max_len: bool,
    ) -> Result<(usize, usize), i64> {
        let lower_offset = self.auxbuf.values_pos as usize;
        // Check to please the verifier.
        if lower_offset > crate::MAX_EVENT_LEN {
            return Err(1);
        }

        let mut read_buffer_len = max_len_to_read;
        if max_len_to_read as u64 > MAX_PARAM_VALUE_LEN as u64 {
            if force_max_len {
                return Err(1);
            }
            read_buffer_len = MAX_PARAM_VALUE_LEN as u16;
        }

        let mut upper_offset = lower_offset + read_buffer_len as usize;
        if upper_offset > crate::MAX_EVENT_LEN {
            if force_max_len {
                return Err(1);
            }
            upper_offset = crate::MAX_EVENT_LEN - lower_offset;
        }
        Ok((lower_offset, upper_offset))
    }

    /// Provide a generic way to write a parameter whose size is known at compile time.
    ///
    /// The user must provide the expected parameter length (`len_to_read`). If the underlying
    /// buffer doesn't have enough space, the operation is aborted. After reserving the requested
    /// amount of bytes, the provided `write_fn` is invoked, receiving as a [ParamWriter] allowing
    /// to write chunks of data on the reserved buffer. In order to abort the operation, `write_fn`
    /// must return an error. The operation can still fail, after running `write_fn`, if the
    /// implementation is not able to write the returned amount of written bytes in the auxiliary
    /// buffer's lengths array.
    pub fn store_fixed_len_param<F>(&mut self, len_to_read: u16, write_fn: F) -> Result<(), i64>
    where
        F: FnOnce(ParamWriter) -> Result<(), i64>,
    {
        let (lower_offset, upper_offset) = self.values_offsets(len_to_read, true)?;
        let param_writer = ParamWriter {
            data: &mut self.auxbuf.data[lower_offset..upper_offset],
        };
        write_fn(param_writer)?;
        self.auxbuf.values_pos += len_to_read as u64;
        self.write_len(len_to_read)?;
        Ok(())
    }
}

/// Helper struct allowing to build a parameter value by exposing a series of method for writing
/// chunk of data over the data buffer reserved for hosting its content.
pub struct ParamWriter<'a> {
    data: &'a mut [u8],
}

impl<'a> ParamWriter<'a> {
    pub fn write_value<T: IntoBytes + Immutable>(&mut self, value: T) -> Result<(), i64> {
        write(&mut self.data, value)
    }

    pub fn as_bytes(&mut self) -> &mut [u8] {
        self.data
    }
}

struct NoBufSpace;

/// Reserve a chunk of bytes of size `value_size` from the buffer pointed by `buf`, returning the
/// reserved chunk and updating `buf` by making it point to the next byte after the reserved chunk.
fn reserve_space<'a, 'b: 'a>(
    buf: &'a mut &'b mut [u8],
    value_size: usize,
) -> Result<&'b mut [u8], NoBufSpace> {
    if buf.len() < value_size {
        return Err(NoBufSpace);
    }

    let (head, tail) = core::mem::take(buf).split_at_mut(value_size);
    *buf = tail;
    Ok(head)
}

/// Write the provided `value` in the buffer pointed by `buf`, and update `buf` to make it point to
/// the next byte after the written value.
fn write<T: IntoBytes + Immutable>(buf: &mut &mut [u8], value: T) -> Result<(), i64> {
    // Keep the API ergonomic by returning an i64 in case of error, which is what the other eBPF
    // code expects in most of the places.
    let reserved_space = reserve_space(buf, size_of::<T>()).map_err(|_| 1)?;
    debug_assert_eq!(reserved_space.len(), size_of::<T>());

    // Don't use `value.as_bytes().write_to(reserved_space)` here as it would return a Result.
    // In case of mismatching lengths, `copy_from_slice` would panic, but since we have reserved the
    // exact required amount of space, we are sure it will never panic.
    reserved_space.copy_from_slice(value.as_bytes());
    Ok(())
}
