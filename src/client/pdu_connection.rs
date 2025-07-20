use anyhow::Result;

/// Трейт для сериализации «PDU» в байты
pub trait ToBytes<const HEADER_LEN: usize>: Sized {
    /// Собрать PDU: вернёт массив заголовка фиксированной длины и вектор данных
    fn to_bytes(self) -> ([u8; HEADER_LEN], Vec<u8>);
}

/// Трейт для десериализации из сырых байт
pub trait FromBytes: Sized {
    const HEADER_LEN: usize;
    type Response;

    /// По заголовку вычисляем полный размер PDU
    fn peek_total_len(header: &[u8]) -> Result<usize>;

    /// Полный парсинг из всего буфера
    fn from_bytes(buf: &[u8]) -> Result<Self::Response>;
}
