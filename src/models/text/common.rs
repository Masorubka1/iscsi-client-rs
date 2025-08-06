bitflags::bitflags! {
    #[derive(Default, Debug, PartialEq)]
    pub struct StageFlags: u8 {
        const FINAL     = 0x80; // bit7
        const CONTINUE  = 0x40; // bit6
    }
}

impl TryFrom<u8> for StageFlags {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        StageFlags::from_bits(value)
            .ok_or_else(|| anyhow::anyhow!("invalid DataOutFlags: {:#08b}", value))
    }
}
