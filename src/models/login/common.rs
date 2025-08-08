use std::fmt;

bitflags::bitflags! {
    #[derive(Default, PartialEq)]
    pub struct LoginFlags: u8 {
        /// Transit bit (next stage)
        const TRANSIT = 0x80;
        /// Continue bit (more text)
        const CONTINUE = 0x40;
        /// Current Stage bits (bits 3-4)
        const CSG_MASK = 0b0000_1100;
        /// Next Stage bits (bits 0-1)
        const NSG_MASK = 0b0000_0011;
    }
}

impl TryFrom<u8> for LoginFlags {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        LoginFlags::from_bits(value)
            .ok_or_else(|| anyhow::anyhow!("invalid LoginFlags: {:#08b}", value))
    }
}

impl fmt::Debug for LoginFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if self.contains(LoginFlags::TRANSIT) {
            parts.push("TRANSIT");
        }
        if self.contains(LoginFlags::CONTINUE) {
            parts.push("CONTINUE");
        }

        match (self.bits() & LoginFlags::CSG_MASK.bits()) >> 2 {
            0 => {},
            1 => parts.push("CSG=Operational"),
            3 => parts.push("CSG=FullFeature"),
            _ => parts.push("CSG=Unknown"),
        }

        match self.bits() & LoginFlags::NSG_MASK.bits() {
            0 => {},
            1 => parts.push("NSG=Operational"),
            3 => parts.push("NSG=FullFeature"),
            _ => parts.push("NSG=Unknown"),
        }

        write!(f, "LoginFlags({})", parts.join("|"))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Stage {
    #[default]
    Security = 0,
    Operational = 1,
    FullFeature = 3,
}

impl Stage {
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b11 {
            0 => Some(Stage::Security),
            1 => Some(Stage::Operational),
            3 => Some(Stage::FullFeature),
            _ => None,
        }
    }
}
