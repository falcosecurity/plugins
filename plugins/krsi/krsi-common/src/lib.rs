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

#![no_std]

pub mod flags;
pub mod scap;

#[derive(Copy, Clone, Debug)]
#[repr(u16)]
pub enum EventType {
    None = 0,
    Open = 1,
    Connect = 2,
    Socket = 3,
    Symlinkat = 4,
    Linkat = 5,
    Unlinkat = 6,
    Mkdirat = 7,
    Renameat = 8,
    Bind = 9,
}

impl Default for EventType {
    fn default() -> Self {
        Self::None
    }
}

impl TryFrom<u16> for EventType {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == EventType::Open as u16 => Ok(EventType::Open),
            x if x == EventType::Connect as u16 => Ok(EventType::Connect),
            x if x == EventType::Socket as u16 => Ok(EventType::Socket),
            x if x == EventType::Symlinkat as u16 => Ok(EventType::Symlinkat),
            x if x == EventType::Linkat as u16 => Ok(EventType::Linkat),
            x if x == EventType::Unlinkat as u16 => Ok(EventType::Unlinkat),
            x if x == EventType::Mkdirat as u16 => Ok(EventType::Mkdirat),
            x if x == EventType::Renameat as u16 => Ok(EventType::Renameat),
            x if x == EventType::Bind as u16 => Ok(EventType::Bind),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct EventHeader {
    pub ts: u64,
    pub tgid_pid: u64,
    pub len: u32,
    pub evt_type: EventType,
    pub nparams: u32,
}
