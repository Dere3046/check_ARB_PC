// Embedded from arb_inspector_next v0.3.0 (MIT License, Copyright 2026 Dere)
// Source: https://github.com/Dere/arb_inspector_next

use sha2::{Sha256, Digest};

// ========== elf.rs ==========
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const PT_PHDR: u32 = 6;
const PF_OS_SEGMENT_TYPE_MASK: u32 = 0x0700_0000;
const PF_OS_ACCESS_TYPE_MASK: u32 = 0x00E0_0000;
const PF_OS_PAGE_MODE_MASK: u32 = 0x0010_0000;
const PF_OS_SEGMENT_HASH: u32 = 0x2;
const PF_OS_ACCESS_NOTUSED: u32 = 0x3;
const PF_OS_ACCESS_SHARED: u32 = 0x4;
const PF_OS_NON_PAGED_SEGMENT: u32 = 0x0;
const PF_OS_PAGED_SEGMENT: u32 = 0x1;
const ELF_BLOCK_ALIGN: u64 = 0x1000;
const ELF32_HDR_SIZE: usize = 52;
const ELF64_HDR_SIZE: usize = 64;
const ELF32_PHDR_SIZE: usize = 32;
const ELF64_PHDR_SIZE: usize = 56;

#[inline]
fn get_os_segment_type(flags: u32) -> u32 {
    (flags & PF_OS_SEGMENT_TYPE_MASK) >> 24
}
#[inline]
fn get_os_access_type(flags: u32) -> u32 {
    (flags & PF_OS_ACCESS_TYPE_MASK) >> 21
}
#[inline]
fn get_os_page_mode(flags: u32) -> u32 {
    (flags & PF_OS_PAGE_MODE_MASK) >> 20
}

// ========== hash_segment.rs ==========
const HASH_TABLE_HEADER_SIZE: usize = 40;
const HASH_TABLE_HEADER_SIZE_V7: usize = 56;
const VERSION_MIN: u32 = 1;
const VERSION_MAX: u32 = 1000;
const COMMON_SIZE_MAX: usize = 0x1000;
const QTI_SIZE_MAX: usize = 0x1000;
const OEM_SIZE_MAX: usize = 0x4000;
const HASH_TABLE_SIZE_MAX: usize = 0x10000;
const ARB_VALUE_MAX: u32 = 127;
const SHA256_SIZE: usize = 32;

// ========== metadata.rs ==========
#[inline]
fn read_le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off+2].try_into().unwrap())
}
#[inline]
fn read_le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off+4].try_into().unwrap())
}
#[inline]
fn read_le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off+8].try_into().unwrap())
}

#[derive(Debug, Clone)]
struct MetadataV00 {
    major_version: u32, minor_version: u32, anti_rollback_version: u32,
}
impl MetadataV00 {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 208 { return Err("Insufficient data"); }
        Ok(Self {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            anti_rollback_version: read_le_u32(data, 312),
        })
    }
    fn get_arb(&self) -> u32 { self.anti_rollback_version }
}

#[derive(Debug, Clone)]
struct MetadataV10 { base: MetadataV00 }
impl MetadataV10 {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        Ok(Self { base: MetadataV00::from_bytes(data)? })
    }
    fn get_arb(&self) -> u32 { self.base.get_arb() }
}

#[derive(Debug, Clone)]
struct MetadataV20 {
    major_version: u32, minor_version: u32, anti_rollback_version: u32,
}
impl MetadataV20 {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 12 { return Err("Insufficient data"); }
        Ok(Self {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            anti_rollback_version: read_le_u32(data, 8),
        })
    }
    fn get_arb(&self) -> u32 { self.anti_rollback_version }
}

#[derive(Debug, Clone)]
struct MetadataV30 { base: MetadataV20 }
impl MetadataV30 {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        Ok(Self { base: MetadataV20::from_bytes(data)? })
    }
    fn get_arb(&self) -> u32 { self.base.get_arb() }
}

#[derive(Debug, Clone)]
struct MetadataV31 { base: MetadataV30 }
impl MetadataV31 {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        Ok(Self { base: MetadataV30::from_bytes(data)? })
    }
    fn get_arb(&self) -> u32 { self.base.get_arb() }
}

#[derive(Debug, Clone)]
enum Metadata {
    V00(MetadataV00), V10(MetadataV10), V20(MetadataV20),
    V30(MetadataV30), V31(MetadataV31),
}
impl Metadata {
    fn from_bytes(data: &[u8], major: u32, minor: u32) -> Result<Self, &'static str> {
        match (major, minor) {
            (0, 0) => Ok(Metadata::V00(MetadataV00::from_bytes(data)?)),
            (1, 0) => Ok(Metadata::V10(MetadataV10::from_bytes(data)?)),
            (2, 0) => Ok(Metadata::V20(MetadataV20::from_bytes(data)?)),
            (3, 0) => Ok(Metadata::V30(MetadataV30::from_bytes(data)?)),
            (3, 1) => Ok(Metadata::V31(MetadataV31::from_bytes(data)?)),
            _ => {
                if data.len() >= 12 {
                    let arb = read_le_u32(data, 8);
                    if arb <= ARB_VALUE_MAX {
                        return Ok(Metadata::V20(MetadataV20 {
                            major_version: major, minor_version: minor,
                            anti_rollback_version: arb,
                        }));
                    }
                }
                Err("Unknown metadata version")
            }
        }
    }
    fn get_arb(&self) -> u32 {
        match self {
            Metadata::V00(m) => m.get_arb(),
            Metadata::V10(m) => m.get_arb(),
            Metadata::V20(m) => m.get_arb(),
            Metadata::V30(m) => m.get_arb(),
            Metadata::V31(m) => m.get_arb(),
        }
    }
    fn version_str(&self) -> String {
        match self {
            Metadata::V00(m) => format!("{}.{}", m.major_version, m.minor_version),
            Metadata::V10(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
            Metadata::V20(m) => format!("{}.{}", m.major_version, m.minor_version),
            Metadata::V30(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
            Metadata::V31(m) => format!("{}.{}", m.base.base.major_version, m.base.base.minor_version),
        }
    }
}

#[derive(Debug, Clone)]
enum CommonMetadata { V00 { major: u32, minor: u32 }, V01 { major: u32, minor: u32 } }
impl CommonMetadata {
    fn from_bytes(data: &[u8], major: u32, minor: u32) -> Result<Self, &'static str> {
        match (major, minor) {
            (0, 0) => Ok(CommonMetadata::V00 {
                major: read_le_u32(data, 0), minor: read_le_u32(data, 4),
            }),
            (0, 1) => Ok(CommonMetadata::V01 {
                major: read_le_u32(data, 0), minor: read_le_u32(data, 4),
            }),
            _ => Err("Unknown common metadata version"),
        }
    }
    fn version_str(&self) -> String {
        match self {
            CommonMetadata::V00 { major, minor } => format!("{}.{}", major, minor),
            CommonMetadata::V01 { major, minor } => format!("{}.{}", major, minor),
        }
    }
}

// ========== main logic ==========
#[derive(Debug)]
struct HashTableSegmentHeader {
    version: u32,
    common_metadata_size: u32,
    oem_metadata_size: u32,
    hash_table_size: u32,
}
impl HashTableSegmentHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < HASH_TABLE_HEADER_SIZE {
            return Err("Insufficient data for hash table header");
        }
        Ok(Self {
            version: read_le_u32(data, 4),
            common_metadata_size: read_le_u32(data, 8),
            oem_metadata_size: read_le_u32(data, 16),
            hash_table_size: read_le_u32(data, 20),
        })
    }
    fn is_plausible(&self) -> bool {
        let common_sz = self.common_metadata_size as usize;
        let oem_sz = self.oem_metadata_size as usize;
        let hash_sz = self.hash_table_size as usize;
        (VERSION_MIN..=VERSION_MAX).contains(&self.version) &&
        common_sz <= COMMON_SIZE_MAX && oem_sz <= OEM_SIZE_MAX &&
        hash_sz > 0 && hash_sz <= HASH_TABLE_SIZE_MAX
    }
    fn header_size(&self) -> usize {
        if self.version == 7 || self.version == 8 {
            HASH_TABLE_HEADER_SIZE_V7
        } else {
            HASH_TABLE_HEADER_SIZE
        }
    }
}

#[derive(Debug)]
struct Elf32ProgramHeader {
    p_type: u32, p_offset: u32, p_vaddr: u32, p_paddr: u32,
    p_filesz: u32, p_memsz: u32, p_flags: u32, p_align: u32,
}
impl Elf32ProgramHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF32_PHDR_SIZE { return Err("Insufficient data for ELF32 PHDR"); }
        Ok(Self {
            p_type: read_le_u32(data, 0), p_offset: read_le_u32(data, 4),
            p_vaddr: read_le_u32(data, 8), p_paddr: read_le_u32(data, 12),
            p_filesz: read_le_u32(data, 16), p_memsz: read_le_u32(data, 20),
            p_flags: read_le_u32(data, 24), p_align: read_le_u32(data, 28),
        })
    }
}

#[derive(Debug)]
struct Elf64ProgramHeader {
    p_type: u32, p_flags: u32, p_offset: u64, p_vaddr: u64,
    p_paddr: u64, p_filesz: u64, p_memsz: u64, p_align: u64,
}
impl Elf64ProgramHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF64_PHDR_SIZE { return Err("Insufficient data for ELF64 PHDR"); }
        Ok(Self {
            p_type: read_le_u32(data, 0), p_flags: read_le_u32(data, 4),
            p_offset: read_le_u64(data, 8), p_vaddr: read_le_u64(data, 16),
            p_paddr: read_le_u64(data, 24), p_filesz: read_le_u64(data, 32),
            p_memsz: read_le_u64(data, 40), p_align: read_le_u64(data, 48),
        })
    }
}

#[derive(Debug)]
struct ProgramHeaderInfo {
    p_type: u32, p_flags: u32, p_offset: u64, p_vaddr: u64,
    p_paddr: u64, p_filesz: u64, p_memsz: u64,
}

#[derive(Debug)]
struct HashTableInfo {
    header: HashTableSegmentHeader,
    common_metadata: Option<CommonMetadata>,
    oem_metadata: Option<Metadata>,
    serial_num: Option<u32>,
    hashes: Vec<Vec<u8>>,
}

fn compute_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

struct ElfWithHashTable {
    elf_class: u8,
    e_entry: u64,
    e_phoff: u64,
    e_phnum: u16,
    e_phentsize: u16,
    e_flags: u32,
    e_machine: u16,
    e_type: u16,
    program_headers: Vec<ProgramHeaderInfo>,
    hash_table_info: Option<HashTableInfo>,
}

impl ElfWithHashTable {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 || &data[0..4] != &ELF_MAGIC {
            return Err("Invalid ELF magic");
        }
        let elf_class = data[EI_CLASS];
        let (e_type, e_machine, e_entry, e_phoff, e_flags, e_phnum, e_phentsize) = match elf_class {
            ELFCLASS32 => {
                if data.len() < ELF32_HDR_SIZE { return Err("Insufficient data for ELF32 header"); }
                (
                    read_le_u16(data, 16), read_le_u16(data, 18),
                    read_le_u32(data, 24) as u64, read_le_u32(data, 28) as u64,
                    read_le_u32(data, 36), read_le_u16(data, 44), read_le_u16(data, 42),
                )
            }
            ELFCLASS64 => {
                if data.len() < ELF64_HDR_SIZE { return Err("Insufficient data for ELF64 header"); }
                (
                    read_le_u16(data, 16), read_le_u16(data, 18),
                    read_le_u64(data, 24), read_le_u64(data, 32),
                    read_le_u32(data, 48), read_le_u16(data, 56), read_le_u16(data, 54),
                )
            }
            _ => return Err("Unsupported ELF class"),
        };

        let mut program_headers = Vec::with_capacity(e_phnum as usize);
        for i in 0..e_phnum {
            let offset = (e_phoff + (i as u64) * (e_phentsize as u64)) as usize;
            if offset + (e_phentsize as usize) > data.len() { continue; }
            let phdr_info = match elf_class {
                ELFCLASS32 => {
                    let phdr = Elf32ProgramHeader::from_bytes(&data[offset..offset + ELF32_PHDR_SIZE])?;
                    ProgramHeaderInfo {
                        p_type: phdr.p_type, p_flags: phdr.p_flags,
                        p_offset: phdr.p_offset as u64, p_vaddr: phdr.p_vaddr as u64,
                        p_paddr: phdr.p_paddr as u64, p_filesz: phdr.p_filesz as u64,
                        p_memsz: phdr.p_memsz as u64,
                    }
                }
                ELFCLASS64 => {
                    let phdr = Elf64ProgramHeader::from_bytes(&data[offset..offset + ELF64_PHDR_SIZE])?;
                    ProgramHeaderInfo {
                        p_type: phdr.p_type, p_flags: phdr.p_flags,
                        p_offset: phdr.p_offset, p_vaddr: phdr.p_vaddr,
                        p_paddr: phdr.p_paddr, p_filesz: phdr.p_filesz,
                        p_memsz: phdr.p_memsz,
                    }
                }
                _ => unreachable!(),
            };
            program_headers.push(phdr_info);
        }

        let mut hash_table_info = None;
        for phdr in &program_headers {
            if get_os_segment_type(phdr.p_flags) == 0x2 { // OS_TYPE_HASH
                let p_offset = phdr.p_offset as usize;
                let p_filesz = phdr.p_filesz as usize;
                if p_offset + p_filesz <= data.len() && p_filesz >= HASH_TABLE_HEADER_SIZE {
                    let header_sz = if data.len() >= p_offset + HASH_TABLE_HEADER_SIZE_V7 {
                        HASH_TABLE_HEADER_SIZE_V7
                    } else {
                        HASH_TABLE_HEADER_SIZE
                    };
                    if let Ok(ht_header) = HashTableSegmentHeader::from_bytes(&data[p_offset..p_offset + header_sz]) {
                        if ht_header.is_plausible() {
                            let header_size = ht_header.header_size();
                            let mut offset = p_offset + header_size;
                            let mut common_metadata = None;
                            let mut oem_metadata = None;
                            let mut serial_num = None;
                            let mut hashes = Vec::new();

                            if ht_header.common_metadata_size > 0 && offset + ht_header.common_metadata_size as usize <= data.len() {
                                let cm_data = &data[offset..offset + ht_header.common_metadata_size as usize];
                                if cm_data.len() >= 8 {
                                    let cm_major = read_le_u32(cm_data, 0);
                                    let cm_minor = read_le_u32(cm_data, 4);
                                    if let Ok(cm) = CommonMetadata::from_bytes(cm_data, cm_major, cm_minor) {
                                        common_metadata = Some(cm);
                                    }
                                }
                                offset += ht_header.common_metadata_size as usize;
                            }

                            if ht_header.oem_metadata_size > 0 && offset + ht_header.oem_metadata_size as usize <= data.len() {
                                let oem_data = &data[offset..offset + ht_header.oem_metadata_size as usize];
                                if oem_data.len() >= 12 {
                                    let oem_major = read_le_u32(oem_data, 0);
                                    let oem_minor = read_le_u32(oem_data, 4);
                                    let arb_candidate = read_le_u32(oem_data, 8);
                                    if ht_header.version == 7 && arb_candidate <= ARB_VALUE_MAX {
                                        oem_metadata = Some(Metadata::V20(MetadataV20 {
                                            major_version: oem_major, minor_version: oem_minor,
                                            anti_rollback_version: arb_candidate,
                                        }));
                                    } else if let Ok(om) = Metadata::from_bytes(oem_data, oem_major, oem_minor) {
                                        oem_metadata = Some(om);
                                    }
                                }
                            }

                            let hash_table_offset = offset;
                            let hash_table_size = ht_header.hash_table_size as usize;
                            if hash_table_offset + hash_table_size <= data.len() && hash_table_size > 0 {
                                let hash_table = &data[hash_table_offset..hash_table_offset + hash_table_size];
                                let mut ht_offset = 0;
                                if hash_table.len() >= SHA256_SIZE * 2 {
                                    let potential_serial = read_le_u32(&hash_table, SHA256_SIZE);
                                    let mut is_valid = true;
                                    for i in 0..SHA256_SIZE {
                                        if hash_table[i] != 0 { is_valid = false; break; }
                                    }
                                    if is_valid && potential_serial != 0 {
                                        serial_num = Some(potential_serial);
                                        ht_offset = SHA256_SIZE * 2;
                                    }
                                }
                                while ht_offset + SHA256_SIZE <= hash_table.len() {
                                    hashes.push(hash_table[ht_offset..ht_offset + SHA256_SIZE].to_vec());
                                    ht_offset += SHA256_SIZE;
                                }
                            }

                            hash_table_info = Some(HashTableInfo {
                                header: ht_header, common_metadata, oem_metadata, serial_num, hashes,
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(Self {
            elf_class, e_entry, e_phoff, e_phnum, e_phentsize, e_flags, e_machine, e_type,
            program_headers, hash_table_info,
        })
    }

    fn get_arb_version(&self) -> Option<u32> {
        self.hash_table_info.as_ref().and_then(|ht| {
            ht.oem_metadata.as_ref().map(|m| m.get_arb())
        })
    }

    fn compute_segment_hashes(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        let mut hashes = Vec::new();
        for phdr in &self.program_headers {
            let flags = phdr.p_flags;
            if get_os_segment_type(flags) == PF_OS_SEGMENT_HASH { continue; }
            let os_access = get_os_access_type(flags);
            if os_access == PF_OS_ACCESS_NOTUSED || os_access == PF_OS_ACCESS_SHARED {
                hashes.push(vec![0u8; SHA256_SIZE]); continue;
            }
            if phdr.p_filesz == 0 { hashes.push(vec![0u8; SHA256_SIZE]); continue; }

            let seg_data = if phdr.p_type == PT_PHDR {
                let start = self.e_phoff as usize;
                let end = start + (self.e_phnum as usize * self.e_phentsize as usize);
                if end <= data.len() { &data[start..end] } else { &[] }
            } else {
                let start = phdr.p_offset as usize;
                let end = start + phdr.p_filesz as usize;
                if end <= data.len() { &data[start..end] } else { &[] }
            };

            let os_page = get_os_page_mode(flags);
            if os_page == PF_OS_NON_PAGED_SEGMENT {
                hashes.push(compute_sha256(seg_data));
            } else if os_page == PF_OS_PAGED_SEGMENT {
                let nonalign = phdr.p_vaddr & (ELF_BLOCK_ALIGN - 1);
                let mut offset = if nonalign != 0 { (ELF_BLOCK_ALIGN - nonalign) as usize } else { 0 };
                let mut page_data = if offset < seg_data.len() { &seg_data[offset..] } else { &[] };
                while page_data.len() >= ELF_BLOCK_ALIGN as usize {
                    hashes.push(compute_sha256(&page_data[..ELF_BLOCK_ALIGN as usize]));
                    page_data = &page_data[ELF_BLOCK_ALIGN as usize..];
                }
            }
        }
        Ok(hashes)
    }
}

// ========== Public API ==========
const VERSION: &str = "0.3.0";

pub fn inspector_version() -> String {
    format!("arb_inspector_next version {}", VERSION)
}

pub struct InspectorResult {
    pub arb: Option<u32>,
    pub elf_class: String,
    pub e_entry: u64,
    pub e_machine: u16,
    pub e_type: u16,
    pub e_flags: u32,
    pub e_phnum: u16,
    pub program_headers: Vec<ProgramHeaderInfo>,
    pub hash_table_info: Option<HashTableInfoOutput>,
    pub computed_hashes: Vec<Vec<u8>>,
    pub debug_output: String,
}

pub struct HashTableInfoOutput {
    pub version: u32,
    pub common_metadata_version: Option<String>,
    pub oem_metadata_version: Option<String>,
    pub oem_arb: Option<u32>,
    pub serial_num: Option<u32>,
    pub hash_count: usize,
}

pub fn inspect_image(path: &str, debug: bool, full: bool) -> Result<InspectorResult, String> {
    let data = std::fs::read(path).map_err(|e| format!("无法读取文件: {}", e))?;

    if data.len() < 8 {
        return Err("文件太小，无法解析".into());
    }

    // Detect type
    let is_elf = data.starts_with(&ELF_MAGIC);
    let is_mbn = if !is_elf {
        let ver = read_le_u32(&data, 4);
        [3, 5, 6, 7, 8].contains(&ver)
    } else { false };

    if !is_elf && !is_mbn {
        return Err("无法识别的文件格式。支持的格式：ELF (bootloader 镜像)".into());
    }

    let mut debug_out = String::new();

    if is_elf {
        if debug {
            debug_out.push_str("[DEBUG] Detected ELF file\n");
        }
        if data[EI_DATA] != ELFDATA2LSB {
            return Err("不是小端序 ELF 文件".into());
        }
        let elf_class = data[EI_CLASS];
        if elf_class != ELFCLASS32 && elf_class != ELFCLASS64 {
            return Err("不支持的 ELF 类别".into());
        }
        if debug {
            debug_out.push_str(&format!("[DEBUG] ELF class: {}\n",
                if elf_class == ELFCLASS32 { "32-bit" } else { "64-bit" }));
        }

        let elf = ElfWithHashTable::from_bytes(&data).map_err(|e| format!("ELF 解析失败: {}", e))?;

        if debug {
            debug_out.push_str(&format!("[DEBUG] ELF entry: 0x{:x}\n", elf.e_entry));
            debug_out.push_str(&format!("[DEBUG] Program header count: {}\n", elf.e_phnum));

            for (i, ph) in elf.program_headers.iter().enumerate() {
                let flags = ph.p_flags;
                let os_seg = get_os_segment_type(flags);
                let os_access = get_os_access_type(flags);
                let os_page = get_os_page_mode(flags);
                debug_out.push_str(&format!(
                    "[DEBUG] PH[{}]: type={:#x} offset=0x{:x} filesz=0x{:x} flags={:#x}\n",
                    i, ph.p_type, ph.p_offset, ph.p_filesz, flags));
                debug_out.push_str(&format!(
                    "[DEBUG]        OS_Seg: {} OS_Access: {} Page: {}\n",
                    os_segment_type_str(os_seg), os_access_type_str(os_access), os_page_mode_str(os_page)));
            }

            match elf.compute_segment_hashes(&data) {
                Ok(hashes) => {
                    debug_out.push_str(&format!("[DEBUG] Computed {} segment hashes:\n", hashes.len()));
                    for (i, h) in hashes.iter().enumerate() {
                        debug_out.push_str(&format!("[DEBUG]   Hash[{}]: {}\n", i,
                            h.iter().map(|b| format!("{:02x}", b)).collect::<String>()));
                    }
                }
                Err(e) => debug_out.push_str(&format!("[DEBUG] Failed to compute segment hashes: {}\n", e)),
            }
        }

        let arb = elf.get_arb_version();

        if debug {
            if let Some(ref ht) = elf.hash_table_info {
                debug_out.push_str(&format!("[DEBUG] Found HASH segment header: version: {}\n", ht.header.version));
                debug_out.push_str(&format!("[DEBUG]   common_metadata_size: {}\n", ht.header.common_metadata_size));
                debug_out.push_str(&format!("[DEBUG]   oem_metadata_size: {}\n", ht.header.oem_metadata_size));
                debug_out.push_str(&format!("[DEBUG]   hash_table_size: {}\n", ht.header.hash_table_size));
            }
            if let Some(v) = arb {
                debug_out.push_str(&format!("[DEBUG] Extracted ARB: {}\n", v));
            }
        }

        let computed_hashes = elf.compute_segment_hashes(&data).unwrap_or_default();

        let hash_table_out = elf.hash_table_info.as_ref().map(|ht| {
            HashTableInfoOutput {
                version: ht.header.version,
                common_metadata_version: ht.common_metadata.as_ref().map(|cm| cm.version_str()),
                oem_metadata_version: ht.oem_metadata.as_ref().map(|om| om.version_str()),
                oem_arb: ht.oem_metadata.as_ref().map(|om| om.get_arb()),
                serial_num: ht.serial_num,
                hash_count: ht.hashes.len(),
            }
        });

        if !full {
            // Quick mode: just ARB
            if let Some(v) = arb {
                if v <= ARB_VALUE_MAX {
                    debug_out.push_str(&format!("{}\n", v));
                } else {
                    debug_out.push_str(&format!("Warning: ARB value {} exceeds expected maximum.\n", v));
                    debug_out.push_str(&format!("{}\n", v));
                }
            } else {
                return Err("未在镜像中找到 ARB 版本".into());
            }
        }

        let elf_class_str = if elf_class == ELFCLASS32 { "32-bit" } else { "64-bit" }.to_string();

        Ok(InspectorResult {
            arb,
            elf_class: elf_class_str,
            e_entry: elf.e_entry,
            e_machine: elf.e_machine,
            e_type: elf.e_type,
            e_flags: elf.e_flags,
            e_phnum: elf.e_phnum,
            program_headers: elf.program_headers,
            hash_table_info: hash_table_out,
            computed_hashes: computed_hashes,
            debug_output: debug_out,
        })
    } else {
        // MBN file
        if debug {
            debug_out.push_str("[DEBUG] Detected MBN 文件\n");
        }
        let version = read_le_u32(&data, 4);
        debug_out.push_str(&format!("MBN 版本: {}\n", version));

        if full {
            let image_id = read_le_u32(&data, 0);
            let image_size = read_le_u32(&data, 16);
            debug_out.push_str(&format!("Image ID: {}\n", image_id));
            debug_out.push_str(&format!("Image Size: {}\n", image_size));
        }

        // Try to find ARB in MBN by scanning for OEM metadata pattern
        let mut arb: Option<u32> = None;
        for i in 0..data.len().saturating_sub(12) {
            let major = read_le_u32(&data, i);
            let minor = read_le_u32(&data, i + 4);
            let arb_val = read_le_u32(&data, i + 8);
            if (major == 2 && minor == 0 && arb_val <= ARB_VALUE_MAX) ||
               (major == 3 && minor == 0 && arb_val <= ARB_VALUE_MAX) ||
               (major == 0 && minor == 0 && arb_val <= ARB_VALUE_MAX) {
                // Verify surrounding data looks like metadata
                if i + 40 <= data.len() {
                    arb = Some(arb_val);
                    if debug {
                        debug_out.push_str(&format!("[DEBUG] Potential ARB found at offset 0x{:x}: {}\n", i, arb_val));
                    }
                    break;
                }
            }
        }

        if let Some(v) = arb {
            debug_out.push_str(&format!("ARB (Anti-Rollback): {}\n", v));
        } else {
            debug_out.push_str("ARB (Anti-Rollback): 未找到\n");
        }

        Ok(InspectorResult {
            arb,
            elf_class: "MBN".to_string(),
            e_entry: 0, e_machine: 0, e_type: 0, e_flags: 0, e_phnum: 0,
            program_headers: Vec::new(),
            hash_table_info: None,
            computed_hashes: Vec::new(),
            debug_output: debug_out,
        })
    }
}

fn os_segment_type_str(t: u32) -> &'static str {
    match t {
        PF_OS_SEGMENT_HASH => "HASH",
        0x7 => "PHDR",
        0x0 => "L4", 0x1 => "AMSS", 0x3 => "BOOT",
        0x4 => "L4BSP", 0x5 => "SWAPPED", 0x6 => "SWAP_POOL",
        _ => "Unknown",
    }
}
fn os_access_type_str(t: u32) -> &'static str {
    match t {
        0x0 => "RW", 0x1 => "RO", 0x2 => "ZI",
        PF_OS_ACCESS_NOTUSED => "NOTUSED", PF_OS_ACCESS_SHARED => "SHARED",
        _ => "Unknown",
    }
}
fn os_page_mode_str(m: u32) -> &'static str {
    match m {
        PF_OS_NON_PAGED_SEGMENT => "NON_PAGED",
        PF_OS_PAGED_SEGMENT => "PAGED",
        _ => "Unknown",
    }
}
