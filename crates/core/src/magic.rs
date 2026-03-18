use serde::{Deserialize, Serialize};

/// High-level file type determined by magic-byte inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    /// Windows Portable Executable (`MZ`).
    PE,
    /// Linux ELF binary (`\x7fELF`).
    ELF,
    /// macOS Mach-O binary (fat or thin, little/big endian).
    MachO,
    /// PDF document (`%PDF`).
    PDF,
    /// ZIP archive (and derivatives like DOCX/XLSX/JAR).
    Zip,
    /// 7-Zip archive (`7z\xBC\xAF\x27\x1C`).
    SevenZip,
    /// tar archive (detected via the `ustar` magic at offset 257).
    Tar,
    /// gzip-compressed stream (`\x1f\x8b`).
    Gzip,
    /// Microsoft Office OLE2 compound document (`\xD0\xCF\x11\xE0`).
    Office,
    /// Script file (starts with `#!`).
    Script,
    /// Unrecognised format.
    Unknown,
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            FileType::PE => "PE",
            FileType::ELF => "ELF",
            FileType::MachO => "Mach-O",
            FileType::PDF => "PDF",
            FileType::Zip => "ZIP",
            FileType::SevenZip => "7z",
            FileType::Tar => "tar",
            FileType::Gzip => "gzip",
            FileType::Office => "Office (OLE2)",
            FileType::Script => "Script",
            FileType::Unknown => "Unknown",
        };
        write!(f, "{}", label)
    }
}

/// Inspect the leading bytes of `data` and return the detected [`FileType`].
///
/// The function requires at most 265 bytes; shorter slices are fine but may
/// cause some formats (e.g. tar) to go undetected.
pub fn detect_magic(data: &[u8]) -> FileType {
    if data.len() < 2 {
        return FileType::Unknown;
    }

    // --- PE (MZ header) ---
    if data.starts_with(b"MZ") || data.starts_with(b"ZM") {
        return FileType::PE;
    }

    // --- ELF ---
    if data.len() >= 4 && data[..4] == [0x7f, b'E', b'L', b'F'] {
        return FileType::ELF;
    }

    // --- Mach-O ---
    if data.len() >= 4 {
        let magic32 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match magic32 {
            // MH_MAGIC, MH_CIGAM (32-bit)
            0xFEED_FACE | 0xCEFA_EDFE |
            // MH_MAGIC_64, MH_CIGAM_64
            0xFEED_FACF | 0xCFFA_EDFE |
            // FAT_MAGIC, FAT_CIGAM (universal binary)
            0xCAFE_BABE | 0xBEBA_FECA => return FileType::MachO,
            _ => {}
        }
    }

    // --- PDF ---
    if data.len() >= 5 && &data[..5] == b"%PDF-" {
        return FileType::PDF;
    }

    // --- ZIP (PK\x03\x04 or PK\x05\x06 empty archive or PK\x07\x08 spanned) ---
    if data.len() >= 4 && data[0] == b'P' && data[1] == b'K' {
        let sig = [data[2], data[3]];
        if sig == [0x03, 0x04] || sig == [0x05, 0x06] || sig == [0x07, 0x08] {
            return FileType::Zip;
        }
    }

    // --- 7-Zip ---
    if data.len() >= 6 && data[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return FileType::SevenZip;
    }

    // --- gzip ---
    if data[0] == 0x1f && data[1] == 0x8b {
        return FileType::Gzip;
    }

    // --- OLE2 Compound Document (legacy Office: .doc, .xls, .ppt) ---
    if data.len() >= 8 && data[..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return FileType::Office;
    }

    // --- tar (POSIX `ustar` magic at byte 257) ---
    if data.len() >= 265 && &data[257..262] == b"ustar" {
        return FileType::Tar;
    }

    // --- Script (shebang) ---
    if data[0] == b'#' && data[1] == b'!' {
        return FileType::Script;
    }

    FileType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_pe() {
        assert_eq!(detect_magic(b"MZ\x90\x00"), FileType::PE);
    }

    #[test]
    fn detect_elf() {
        assert_eq!(detect_magic(b"\x7fELF\x02\x01\x01"), FileType::ELF);
    }

    #[test]
    fn detect_pdf() {
        assert_eq!(detect_magic(b"%PDF-1.7 ..."), FileType::PDF);
    }

    #[test]
    fn detect_zip() {
        assert_eq!(detect_magic(b"PK\x03\x04extra"), FileType::Zip);
    }

    #[test]
    fn detect_gzip() {
        assert_eq!(detect_magic(&[0x1f, 0x8b, 0x08, 0x00]), FileType::Gzip);
    }

    #[test]
    fn detect_7z() {
        assert_eq!(
            detect_magic(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00]),
            FileType::SevenZip
        );
    }

    #[test]
    fn detect_ole2_office() {
        assert_eq!(
            detect_magic(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00]),
            FileType::Office
        );
    }

    #[test]
    fn detect_script() {
        assert_eq!(detect_magic(b"#!/bin/bash\n"), FileType::Script);
    }

    #[test]
    fn detect_tar() {
        let mut buf = vec![0u8; 300];
        buf[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_magic(&buf), FileType::Tar);
    }

    #[test]
    fn detect_unknown() {
        assert_eq!(detect_magic(b"\x00\x00\x00\x00"), FileType::Unknown);
    }

    #[test]
    fn empty_data() {
        assert_eq!(detect_magic(b""), FileType::Unknown);
        assert_eq!(detect_magic(b"\x00"), FileType::Unknown);
    }

    #[test]
    fn detect_macho_64() {
        let magic: [u8; 4] = 0xFEED_FACFu32.to_be_bytes();
        assert_eq!(detect_magic(&magic), FileType::MachO);
    }
}
