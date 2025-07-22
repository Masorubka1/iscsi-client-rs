use std::fmt;

bitflags::bitflags! {
    #[derive(Clone, PartialEq)]
    pub struct NopFlags: u8 {
        /// Ping bit
        const PING = 0x40;
        /// Ping resp opcode
        const NOP_OUT = 0x00;
        /// Pong resp opcode
        const NOP_IN = 0x20;
    }
}

impl fmt::Debug for NopFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if self.contains(NopFlags::PING) {
            parts.push("PING");
        }

        if self.contains(NopFlags::NOP_IN) {
            parts.push("NOP_IN");
        } else {
            parts.push("NOP_OUT");
        }

        write!(f, "NopFlags({})", parts.join("|"))
    }
}
