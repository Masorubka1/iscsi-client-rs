// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Mask that selects the upper 1 bits (**F**) from the first BHS byte.
const FINAL_FLAG: u8 = 0b1000_0000;
/// Mask that selects the upper 1 bits (**C**) from the first BHS byte.
const CONTINUE_FLAG: u8 = 0b0100_0000;

#[repr(transparent)]
#[derive(Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawStageFlags(u8);

impl RawStageFlags {
    #[inline]
    pub const fn get_final_bit(&self) -> bool {
        (self.0 & FINAL_FLAG) != 0
    }

    #[inline]
    pub fn set_final_bit(&mut self) {
        self.0 ^= FINAL_FLAG
    }

    #[inline]
    pub const fn get_continue_bit(&self) -> bool {
        (self.0 & CONTINUE_FLAG) != 0
    }

    #[inline]
    pub fn set_continue_bit(&mut self) {
        self.0 ^= CONTINUE_FLAG
    }
}
