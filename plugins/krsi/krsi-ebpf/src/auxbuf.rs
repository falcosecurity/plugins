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

use crate::MAX_EVENT_LEN;

/// Auxiliary buffer length.
///
/// It must be able to contain an event of [MAX_EVENT_LEN], but it is set to its double in order to
/// please the verifier.
const AUXILIARY_BUFFER_LEN: usize = MAX_EVENT_LEN * 2;

/// The maximum number of parameters that can be stored in an auxiliary buffer.
///
/// # Formula explanation
/// Calling `X` the maximum number of parameters, and being a parameter length expressed as `u16`
/// (2 bytes), the amount of bytes to store their lengths is `2 * X` bytes.
/// Assuming an occupation of just 1 byte for each of the `X` parameters, the total amount of
/// required bytes, occupied by both lengths and values, would be `3 * X`.
/// By taking into account this, and the fact that the buffer must also accommodate the event
/// header, the following equation can be written:
/// `3 * X = MAX_EVENT_LEN - size_of::<EventHeader>()`. The final formula is obtained by dividing
/// both sides of the equation by 3.
const MAX_PARAMS_NUM: usize = (MAX_EVENT_LEN - size_of::<EventHeader>()) / 3;

/// Store the configuration of a [Writer] instance. See [Writer::save],
/// [AuxiliaryBuffer::save_writer_state] and [AuxiliaryBuffer::resume_writer] for more details.
pub struct WriterState {
    /// The amount of bytes not yet filled in the auxiliary buffer's lengths vector.
    remaining_lengths_room: usize,
    /// The amount of bytes not yet filled in the auxiliary buffer's values list.
    remaining_values_room: usize,
}

pub struct AuxiliaryBuffer {
    /// Raw space to save the variable-size event. See [AUXILIARY_BUFFER_LEN] for more details on
    /// the effective available space.
    data: [u8; AUXILIARY_BUFFER_LEN],
    /// Saved writer state. See [WriterState] for more details.
    saved_writer_state: Option<WriterState>,
}

impl AuxiliaryBuffer {
    /// Create a new [Writer] instance associated with the buffer.
    pub fn writer(
        &mut self,
        ts: u64,
        tgid_pid: u64,
        event_type: EventType,
        nparams: u32,
    ) -> Result<Writer, i64> {
        if nparams > MAX_PARAMS_NUM as u32 {
            return Err(1);
        }

        let (header, bufs) = self.data[..MAX_EVENT_LEN].split_at_mut(size_of::<EventHeader>());
        let lengths_len = (nparams as usize) * size_of::<u16>();

        // Notice: `event_header_mut_from_bytes()` can never return an error (see
        // `AuxiliaryBuffer::event_header_mut_from_bytes()` for more details).
        let header = Self::event_header_mut_from_bytes(header)?;
        header.ts = ts.into();
        header.tgid_pid = tgid_pid.into();
        header.len = ((size_of::<EventHeader>() + lengths_len) as u32).into();
        header.evt_type = (event_type as u16).into();
        header.nparams = nparams.into();

        let (lengths, values) = bufs.split_at_mut(lengths_len);

        self.saved_writer_state = None;

        Ok(Writer {
            header,
            lengths,
            values,
        })
    }

    /// Create a new [Writer] instance, associated with the buffer, using the saved writer state.
    /// For the call to be successful, the user must have first saved a writer state via a previous
    /// call to [AuxiliaryBuffer::saved_writer_state].
    pub fn resume_writer(&mut self) -> Result<Writer, i64> {
        // While verifying if there is any saved state, set it to None if any.
        let Some(WriterState {
            remaining_lengths_room,
            remaining_values_room,
        }) = self.saved_writer_state.take()
        else {
            return Err(1);
        };

        let (header, bufs) = self.data[..MAX_EVENT_LEN].split_at_mut(size_of::<EventHeader>());
        let header = Self::event_header_mut_from_bytes(header)?;
        let nparams = header.nparams.get();
        // Check to please the verifier: as long as nparams is set by `writer()`, its value cannot
        // be greater than `MAX_PARAMS_NUM`.
        if nparams > MAX_PARAMS_NUM as u32 {
            return Err(1);
        }

        let lengths_len = (nparams as usize) * size_of::<u16>();
        let (mut lengths, mut values) = bufs.as_mut().split_at_mut(lengths_len);
        let values_len = values.len();
        // Use saturating_sub to please the verifier, but actually remaining_lengths_room and
        // remaining_values_room cannot be greater than lengths_len and values_len.
        let lengths_bytes_to_skip = lengths_len.saturating_sub(remaining_lengths_room);
        let values_bytes_to_skip = values_len.saturating_sub(remaining_values_room);
        skip_u8_slice_bytes(&mut lengths, lengths_bytes_to_skip);
        skip_u8_slice_bytes(&mut values, values_bytes_to_skip);
        Ok(Writer {
            header,
            lengths,
            values,
        })
    }

    /// Save the writer state to enable resuming it later via [Self::resume_writer].
    pub fn save_writer_state(&mut self, state: WriterState) {
        self.saved_writer_state = Some(state);
    }

    /// Return a slice to the underlying data. The slice length can never exceed [MAX_EVENT_LEN].
    pub fn as_bytes(&self) -> Result<&[u8], i64> {
        let header_bytes = &self.data[..size_of::<EventHeader>()];
        // Notice: `event_header_ref_from_bytes()` can never return an error (see
        // `AuxiliaryBuffer::event_header_ref_from_bytes()` for more details).
        let len = Self::event_header_ref_from_bytes(header_bytes)?.len.get() as usize;
        // Actually, header.len value can never be greater than `MAX_EVENT_LEN` because the code
        // prevent the data in the buffer to grow above this limit, but here we only check for
        // out-of-bound values.
        if len > self.data.len() {
            return Err(1);
        }
        Ok(&self.data[..len])
    }

    /// Interpret the provided bytes as an immutable reference to [EventHeader].
    ///
    /// Notice: this call actually cannot return an error, but it internally uses
    /// [FromBytes::ref_from_bytes] which can returns an error, and sadly there is no other
    /// conversion helper performing this infallible conversion in an unchecked way.
    fn event_header_ref_from_bytes(header_bytes: &[u8]) -> Result<&EventHeader, i64> {
        debug_assert_eq!(header_bytes.len(), size_of::<EventHeader>());
        EventHeader::ref_from_bytes(header_bytes).map_err(|_| 1)
    }

    /// Interpret the provided bytes as a mutable reference to [EventHeader].
    ///
    /// Notice: this call actually cannot return an error, but it internally uses
    /// [FromBytes::mut_from_bytes] which can returns an error, and sadly there is no other
    /// conversion helper performing this infallible conversion in an unchecked way.
    fn event_header_mut_from_bytes(header_bytes: &mut [u8]) -> Result<&mut EventHeader, i64> {
        debug_assert_eq!(header_bytes.len(), size_of::<EventHeader>());
        EventHeader::mut_from_bytes(header_bytes).map_err(|_| 1)
    }
}

/// Utility allowing to push data on an [AuxiliaryBuffer].
pub struct Writer<'a> {
    header: &'a mut EventHeader,
    lengths: &'a mut [u8],
    values: &'a mut [u8],
}

impl<'a> Writer<'a> {
    pub fn finalize_event_header(&mut self) {
        // Notice: `self.header.len` value is set to
        // `size_of::<EventHeader>() + self.header.nparams * size_of::<u16>()` upon writer
        // instantiation. Update its value to include also the written values bytes.
        let len = self.header.len.get() as usize;
        let total_values_bytes = MAX_EVENT_LEN - len;
        let written_values_bytes = total_values_bytes - self.values.len();
        self.header.len = ((len + written_values_bytes) as u32).into();
    }

    pub fn store_param<T: IntoBytes + Immutable>(&mut self, param: T) -> Result<(), i64> {
        self.write_value(param)?;
        self.write_len(size_of::<T>() as u16)
    }

    fn write_value<T: IntoBytes + Immutable>(&mut self, value: T) -> Result<(), i64> {
        write(&mut self.values, value)
    }

    fn write_len(&mut self, value: u16) -> Result<(), i64> {
        write(&mut self.lengths, value)
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
        let len_to_reserve = self.len_to_reserve(max_len_to_read as usize, force_max_len)?;
        let param_writer = ParamWriter {
            data: &mut self.values[..len_to_reserve],
        };
        let written_bytes = write_fn(param_writer)?;
        // FIXME(ekoops): this check must be written_bytes > len_to_reserve, but changing it would
        //   result in `Verifier output: last insn is not an exit or jmp.`.
        if written_bytes >= len_to_reserve as u16 {
            return Err(1);
        }

        skip_u8_slice_bytes(&mut self.values, written_bytes as usize);
        self.write_len(written_bytes)?;
        Ok(written_bytes)
    }

    fn len_to_reserve(
        &mut self,
        max_len_to_read: usize,
        force_max_len: bool,
    ) -> Result<usize, i64> {
        let values_len = self.values.len();
        if max_len_to_read <= values_len {
            Ok(max_len_to_read)
        } else if !force_max_len {
            Ok(values_len)
        } else {
            Err(1)
        }
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
        let len_to_reserve = self.len_to_reserve(len_to_read as usize, true)?;
        let param_writer = ParamWriter {
            data: &mut self.values[..len_to_reserve],
        };
        write_fn(param_writer)?;
        skip_u8_slice_bytes(&mut self.values, len_to_reserve);
        self.write_len(len_to_read)?;
        Ok(())
    }

    /// Save the current state in an object that can be used to restore the writer instance later.
    pub fn save(self) -> WriterState {
        WriterState {
            remaining_lengths_room: self.lengths.len(),
            remaining_values_room: self.values.len(),
        }
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

/// Shrink the byte buffer pointed by `slice` by removing `bytes_to_skip` bytes from its beginning.
fn skip_u8_slice_bytes(slice: &mut &mut [u8], bytes_to_skip: usize) {
    let old_slice = core::mem::take(slice);
    *slice = &mut old_slice[bytes_to_skip..];
}

/// Write the provided `value` in the buffer pointed by `buf`, and update `buf` to make it point to
/// the next byte after the written value.
fn write<T: IntoBytes + Immutable>(buf: &mut &mut [u8], value: T) -> Result<(), i64> {
    // Keep the API ergonomic by returning an i64 in case of error, which is what the other eBPF
    // code expects in most of the places.
    let reserved_space = reserve_space(buf, size_of::<T>()).map_err(|_| 1)?;

    // Don't use `value.as_bytes().write_to(reserved_space)` here as it would return a Result.
    // In case of mismatching lengths, `copy_from_slice` would panic, but since we have reserved the
    // exact required amount of space, we are sure it will never panic.
    debug_assert_eq!(reserved_space.len(), size_of::<T>());
    reserved_space.copy_from_slice(value.as_bytes());
    Ok(())
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
