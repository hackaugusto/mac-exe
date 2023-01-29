#![feature(iter_is_partitioned)]
#![allow(dead_code)]
use repr_trait::Packed;
use std::io::{Seek, SeekFrom};
use std::slice;

trait ToBytes {
    fn len() -> usize;

    /// Borrows the memory of the current instance.
    ///
    /// Note: Because of endianness this is not a cross platform representation.
    fn to_bytes<'a>(&'a self) -> &'a [u8];
}

impl<T> ToBytes for T
where
    T: Sized + Packed,
{
    fn len() -> usize {
        std::mem::size_of::<T>()
    }

    fn to_bytes<'a>(&'a self) -> &'a [u8] {
        let size = Self::len();
        let bytes_ptr = self as *const _ as *const u8;
        unsafe { slice::from_raw_parts(bytes_ptr, size) }
    }
}

// References:
//
// https://lowlevelbits.org/parsing-mach-o-files/
// https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html
// http://idea2ic.com/File_Formats/MachORuntime.pdf
// https://github.com/aidansteele/osx-abi-macho-file-format-reference
// http://www.newosxbook.com/articles/DYLD.html#footnote
//
// /System/Volumes/Data/Library/Developer/CommandLineTools/SDKs/MacOSX12.3.sdk/usr/include/mach-o
// /System/Volumes/Data/Library/Developer/CommandLineTools/SDKs/MacOSX12.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach-o/
// /System/Volumes/Data/Library/Developer/CommandLineTools/SDKs/MacOSX13.1.sdk/usr/include/mach-o/
// /System/Volumes/Data/Library/Developer/CommandLineTools/SDKs/MacOSX13.1.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach-o/
// /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk/usr/include/mach-o/
// /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach-o/
// /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/mach-o/
// llvm-project/lldb/source/Plugins/ObjectFile/Mach-O/ObjectFileMachO.h
// llvm-project/lldb/source/Plugins/ObjectContainer/Universal-Mach-O/ObjectContainerUniversalMachO.h
// llvm-project/libunwind/include/mach-o/compact_unwind_encoding.h
// zig/libc/include/any-macos-any/mach-o/arch.h
// zig/libc/include/any-macos.11-any/mach-o/loader.h
//
// /System/Volumes/Data/Users/hack/code/rust/src/llvm-project/libunwind/include/mach-o/compact_unwind_encoding.h
// /System/Volumes/Data/Users/hack/code/rust/src/llvm-project/lldb/source/Plugins/ObjectFile/Mach-O/ObjectFileMachO.h
// /System/Volumes/Data/Users/hack/code/rust/src/llvm-project/lldb/source/Plugins/ObjectContainer/Universal-Mach-O/ObjectContainerUniversalMachO.h
// /opt/homebrew/Cellar/zig/0.10.0/lib/zig/libc/include/any-macos-any/mach-o/arch.h
// /opt/homebrew/Cellar/zig/0.10.0/lib/zig/libc/include/any-macos.11-any/mach-o/loader.h

use std::io::Result as IOResult;
use std::io::Write;
use std::mem::size_of;
use std::{env::args, fs::File};

#[repr(transparent)]
#[derive(PartialEq)]
struct VirtualMemory(usize);

#[repr(transparent)]
struct SectionNumber(usize);

const VIRTUAL_MEMORY_BOUNDARY: VirtualMemory = VirtualMemory(4096);

/// A variable length string in a load command is represented by an lc_str union.  The strings are
/// stored just after the load command structure and the offset is from the start of the load
/// command structure.  The size of the string is reflected in the cmdsize field of the load
/// command. Once again any padded bytes to bring the cmdsize field to a multiple of 4 bytes must
/// be zero.
#[derive(Debug, Copy, Clone)]
enum LcStr {
    Offset(u32), // offset to the string
}

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum Magic64 {
    // Constant for the magic field of the mach_header_64 (64-bit architectures)
    MH_MAGIC_64 = 0xfeedfacf,
    MH_CIGAM_64 = 0xcffaedfe,
}

#[allow(non_camel_case_types)]
#[repr(u32)] // (mach/machine.h) typedef integer_t cpu_type_t;
#[derive(Debug, Copy, Clone)]
enum CpuType {
    CPU_TYPE_ARM64 = 0x0100000c,
}

#[allow(non_camel_case_types)]
#[repr(u32)] // (mach/machine.h) typedef integer_t cpu_subtype_t;
#[derive(Debug, Copy, Clone)]
enum CpuSubtype {
    CPU_SUBTYPE_ARM64_ALL = 0,
}

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum FileType {
    MH_EXECUTE = 2,
}

/// The layout of the file depends on the filetype.  For all but the MH_OBJECT file type the
/// segments are padded out and aligned on a segment alignment boundary for efficient demand
/// pageing.  The MH_EXECUTE, MH_FVMLIB, MH_DYLIB, MH_DYLINKER and MH_BUNDLE file types also have
/// the headers included as part of their first segment.
///
/// The file type MH_OBJECT is a compact format intended as output of the assembler and input (and
/// possibly output) of the link editor (the .o format).  All sections are in one unnamed segment
/// with no segment padding. This format is used as an executable format when the file is so small
/// the segment padding greatly increases its size.
///
/// The file type MH_PRELOAD is an executable format intended for things that are not executed
/// under the kernel (proms, stand alones, kernels, etc).  The format can be executed under the
/// kernel but may demand paged it and not preload it before execution.
///
/// A core file is in MH_CORE format and can be any in an arbritray legal Mach-O file.
///
/// Constants for the filetype field of the mach_header
#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Copy, Clone, Debug)]
enum HeaderFlags {
    MH_PIE = 0x200000, // When this bit is set, the OS will load the main executable at a random address. Only used in MH_EXECUTE filetypes.
    MH_TWOLEVEL = 0x80, // the image is using two-level name space bindings
    MH_DYLDLINK = 0x4, // the object file is input for the dynamic linker and can't be staticly link edited again
    MH_NOUNDEFS = 0x1, // the object file has no undefined references
}

/// The 64-bit mach header appears at the very beginning of object files for 64-bit architectures.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct Header64 {
    magic: Magic64,         // mach magic number identifier
    cputtype: CpuType,      // cpu specifier
    cpusubtype: CpuSubtype, // machine specifier
    filetype: FileType,     // type of file
    ncmds: u32,             // number of load commands
    sizeofcmds: u32,        // the size of all the load commands
    flags: u32,             // flags
    reserved: u32,          // reserved
}

/// The load commands directly follow the mach_header. The total size of all of the commands is
/// given by the sizeofcmds field in the mach_header. All load commands must have as their first
/// two fields cmd and cmdsize. The cmd field is filled in with a constant for that command type.
/// Each command type has a structure specifically for it. The cmdsize field is the size in bytes
/// of the particular load command structure plus anything that follows it that is a part of the
/// load command (i.e. section structures, strings, etc.). To advance to the next load command the
/// cmdsize can be added to the offset or pointer of the current load command. The cmdsize for
/// 32-bit architectures MUST be a multiple of 4 bytes and for 64-bit architectures MUST be a
/// multiple of 8 bytes (these are forever the maximum alignment of any load commands). The padded
/// bytes must be zero. All tables in the object file must also follow these rules so the file can
/// be memory mapped. Otherwise the pointers to these tables will not work well or at all on some
/// machines. With all padding zeroed like objects will compare byte for byte.
#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum Command {
    // After MacOS X 10.1 when a new load command is added that is required to be
    // understood by the dynamic linker for the image to execute properly the
    // LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
    // linker sees such a load command it it does not understand will issue a
    // "unknown load command required for execution" error and refuse to use the
    // image. Other load commands without this bit that are not understood will
    // simply be ignored.
    LC_REQ_DYLD = 0x80000000,

    // Constants for the cmd field of all load commands, the type
    LC_SEGMENT = 0x1,         // segment of this file to be mapped
    LC_SYMTAB = 0x2,          // link-edit stab symbol table info
    LC_SYMSEG = 0x3,          // link-edit gdb symbol table info (obsolete)
    LC_THREAD = 0x4,          // thread
    LC_UNIXTHREAD = 0x5,      // unix thread (includes a stack)
    LC_LOADFVMLIB = 0x6,      // load a specified fixed VM shared library
    LC_IDFVMLIB = 0x7,        // fixed VM shared library identification
    LC_IDENT = 0x8,           // object identification info (obsolete)
    LC_FVMFILE = 0x9,         // fixed VM file inclusion (internal use)
    LC_PREPAGE = 0xa,         // prepage command (internal use)
    LC_DYSYMTAB = 0xb,        // dynamic link-edit symbol table info
    LC_LOAD_DYLIB = 0xc,      // load a dynamically linked shared library
    LC_ID_DYLIB = 0xd,        // dynamically linked shared lib ident
    LC_LOAD_DYLINKER = 0xe,   // load a dynamic linker
    LC_ID_DYLINKER = 0xf,     // dynamic linker identification
    LC_PREBOUND_DYLIB = 0x10, // modules prebound for a dynamically */ /*  linked shared library
    LC_ROUTINES = 0x11,       // image routines
    LC_SUB_FRAMEWORK = 0x12,  // sub framework
    LC_SUB_UMBRELLA = 0x13,   // sub umbrella
    LC_SUB_CLIENT = 0x14,     // sub client
    LC_SUB_LIBRARY = 0x15,    // sub library
    LC_TWOLEVEL_HINTS = 0x16, // two-level namespace lookup hints
    LC_PREBIND_CKSUM = 0x17,  // prebind checksum

    /*
     * load a dynamically linked shared library that is allowed to be missing
     * (all symbols are weak imported).
     */
    LC_LOAD_WEAK_DYLIB = 0x80000018,     // (0x18 | LC_REQ_DYLD)
    LC_SEGMENT_64 = 0x19,                // 64-bit segment of this file to be mapped
    LC_ROUTINES_64 = 0x1a,               // 64-bit image routines
    LC_UUID = 0x1b,                      // the uuid
    LC_RPATH = 0x8000001c,               // (0x1c | LC_REQ_DYLD) runpath additions
    LC_CODE_SIGNATURE = 0x1d,            // local of code signature
    LC_SEGMENT_SPLIT_INFO = 0x1e,        // local of info to split segments
    LC_REEXPORT_DYLIB = 0x8000001f,      // (0x1f | LC_REQ_DYLD) load and re-export dylib
    LC_LAZY_LOAD_DYLIB = 0x20,           // delay load of dylib until first use
    LC_ENCRYPTION_INFO = 0x21,           // encrypted segment information
    LC_DYLD_INFO = 0x22,                 // compressed dyld information
    LC_DYLD_INFO_ONLY = 0x80000022,      // (0x22|LC_REQ_DYLD)	compressed dyld information only
    LC_LOAD_UPWARD_DYLIB = 0x80000023,   // (0x23 | LC_REQ_DYLD) load upward dylib
    LC_VERSION_MIN_MACOSX = 0x24,        // build for MacOSX min OS version
    LC_VERSION_MIN_IPHONEOS = 0x25,      // build for iPhoneOS min OS version
    LC_FUNCTION_STARTS = 0x26,           // compressed table of function start addresses
    LC_DYLD_ENVIRONMENT = 0x27,          // string for dyld to treat like environment variable
    LC_MAIN = 0x80000028,                // (0x28|LC_REQ_DYLD) replacement for LC_UNIXTHREAD
    LC_DATA_IN_CODE = 0x29,              // table of non-instructions in __text
    LC_SOURCE_VERSION = 0x2A,            // source version used to build binary
    LC_DYLIB_CODE_SIGN_DRS = 0x2B,       // Code signing DRs copied from linked dylibs
    LC_ENCRYPTION_INFO_64 = 0x2C,        // 64-bit encrypted segment information
    LC_LINKER_OPTION = 0x2D,             // linker options in MH_OBJECT files
    LC_LINKER_OPTIMIZATION_HINT = 0x2E,  // optimization hints in MH_OBJECT files
    LC_VERSION_MIN_TVOS = 0x2F,          // build for AppleTV min OS version
    LC_VERSION_MIN_WATCHOS = 0x30,       // build for Watch min OS version
    LC_NOTE = 0x31,                      // arbitrary data included within a Mach-O file
    LC_BUILD_VERSION = 0x32,             // build for platform min OS version
    LC_DYLD_EXPORTS_TRIE = 0x80000033, // (0x33 | LC_REQ_DYLD) used with linkedit_data_command, payload is trie
    LC_DYLD_CHAINED_FIXUPS = 0x80000034, // (0x34 | LC_REQ_DYLD) used with linkedit_data_command
    LC_FILESET_ENTRY = 0x80000035,     // (0x35 | LC_REQ_DYLD) used with fileset_entry_command
}

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Copy, Clone, Debug)]
enum SegmentCommandFlags {
    VM_PROT_NONE = 0x00,
    VM_PROT_READ = 0x01,    // read permission
    VM_PROT_WRITE = 0x02,   // write permission
    VM_PROT_EXECUTE = 0x04, // execute permission
}

/// The segment load command indicates that a part of this file is to be mapped into the task's
/// address space. The size of this segment in memory, vmsize, maybe equal to or larger than the
/// amount to map from this file, filesize. The file is mapped starting at fileoff to the
/// beginning of the segment in memory, vmaddr. The rest of the memory of the segment, if any, is
/// allocated zero fill on demand. The segment's maximum virtual memory protection and initial
/// virtual memory protection are specified by the maxprot and initprot fields. If the segment has
/// sections then the section structures directly follow the segment command and their size is
/// reflected in cmdsize.
///
/// The 64-bit segment load command indicates that a part of this file is to be mapped into a
/// 64-bit task's address space. If the 64-bit segment has sections then section_64 structures
/// directly follow the 64-bit segment command and their size is reflected in cmdsize.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct SegmentCommand64 {
    cmd: Command,      // LC_SEGMENT_64
    cmdsize: u32,      // includes sizeof section_64 structs
    segname: [u8; 16], // segment name
    vmaddr: u64,       // memory address of this segment
    vmsize: u64,       // memory size of this segment
    fileoff: u64,      // file offset of this segment
    filesize: u64,     // amount to map from the file
    maxprot: u32,      // maximum VM protection
    initprot: u32,     // initial VM protection
    nsects: u32,       // number of sections in segment
    flags: u32,        // flags
}

/// The linkedit_data_command contains the offsets and sizes of a blob of data in the __LINKEDIT
/// segment.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct LinkEditDataCommand {
    // LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO, LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
    // LC_DYLIB_CODE_SIGN_DRS, LC_LINKER_OPTIMIZATION_HINT, LC_DYLD_EXPORTS_TRIE, or
    // LC_DYLD_CHAINED_FIXUPS.
    cmd: Command,
    cmdsize: u32,  // sizeof(struct linkedit_data_command)
    dataoff: u32,  // file offset of data in __LINKEDIT segment
    datasize: u32, // file size of data in __LINKEDIT segment
}

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum SectionFlags {
    S_REGULAR = 0x00000000,
    S_ATTR_PURE_INSTRUCTIONS = 0x80000000, // section contains only true machine instructions
    S_ATTR_SOME_INSTRUCTIONS = 0x00000400, // section contains some machine instructions
}

#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct Section64 {
    sectname: [u8; 16], // name of this section
    segname: [u8; 16],  // segment this section goes in
    addr: u64,          // memory address of this section
    size: u64,          // size in bytes of this section
    offset: u32,        // file offset of this section
    align: u32,         // section alignment (power of 2)
    reloff: u32,        // file offset of relocation entries
    nreloc: u32,        // number of relocation entries
    flags: u32,         // flags (section type and attributes
    reserved1: u32,     // reserved (for offset or index)
    reserved2: u32,     // reserved (for count or sizeof)
    reserved3: u32,     // reserved
}

/// The symtab_command contains the offsets and sizes of the link-edit 4.3BSD "stab" style symbol
/// table information as described in the header files <nlist.h> and <stab.h>.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct SymtabCommand {
    cmd: Command, // LC_SYMTAB
    cmdsize: u32, // sizeof(struct symtab_command)
    symoff: u32,  // symbol table offset
    nsyms: u32,   // number of symbol table entries
    stroff: u32,  // string table offset
    strsize: u32, // string table size in bytes
}

/// This is the second set of the symbolic information which is used to support the data structures
/// for the dynamically link editor.
///
/// The original set of symbolic information in the symtab_command which contains the symbol and
/// string tables must also be present when this load command is present.  When this load command
/// is present the symbol table is organized into three groups of symbols:
///
///  - local symbols (static and debugging symbols)
///  - grouped by module defined external symbols
///  - grouped by module (sorted by name if not lib)
///  - undefined external symbols (sorted by name if MH_BINDATLOAD is not set, and in order the
///  were seen by the static linker if MH_BINDATLOAD is set)
///
/// In this load command there are offsets and counts to each of the three groups of symbols.
///
/// This load command contains a the offsets and sizes of the following new symbolic information
/// tables:
///
///  - table of contents
///  - module table
///  - reference symbol table
///  - indirect symbol table
///
/// The first three tables above (the table of contents, module table and reference symbol table)
/// are only present if the file is a dynamically linked shared library. For executable and object
/// modules, which are files containing only one module, the information that would be in these
/// three tables is determined as follows:
///
/// - table of contents: the defined external symbols are sorted by name
/// - module table: the file contains only one module so everything in the file is part of the module.
/// - reference symbol table: is the defined and undefined external symbols
///
/// For dynamically linked shared library files this load command also contains offsets and sizes
/// to the pool of relocation entries for all sections separated into two groups:
///
///  - external relocation entries
///  - local relocation entries
///
/// For executable and object modules the relocation entries continue to hang off the section
/// structures.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct DysymtabCommand {
    cmd: Command, /* LC_DYSYMTAB */
    cmdsize: u32, /* sizeof(struct dysymtab_command) */

    /// The symbols indicated by symoff and nsyms of the LC_SYMTAB load command are grouped into
    /// the following three groups:
    ///
    ///    - local symbols (further grouped by the module they are from)
    ///    - defined external symbols (further grouped by the module they are from) undefined
    ///    symbols
    ///
    /// The local symbols are used only for debugging. The dynamic binding process may have to use
    /// them to indicate to the debugger the local symbols for a module that is being bound.
    ///
    /// The last two groups are used by the dynamic binding process to do the binding (indirectly
    /// through the module table and the reference symbol table when this is a dynamically linked
    /// shared library file).
    ilocalsym: u32, // index to local symbols
    nlocalsym: u32, // number of local symbols

    iextdefsym: u32, // index to externally defined symbols
    nextdefsym: u32, // number of externally defined symbols

    iundefsym: u32, // index to undefined symbols
    nundefsym: u32, // number of undefined symbols

    /// For the for the dynamic binding process to find which module a symbol is defined in the
    /// table of contents is used (analogous to the ranlib structure in an archive) which maps
    /// defined external symbols to modules they are defined in. This exists only in a dynamically
    /// linked shared library file. For executable and object modules the defined external symbols
    /// are sorted by name and is use as the table of contents.
    tocoff: u32, // file offset to table of contents
    ntoc: u32, // number of entries in table of contents

    /// To support dynamic binding of "modules" (whole object files) the symbol table must reflect
    /// the modules that the file was created from.  This is done by having a module table that has
    /// indexes and counts into the merged tables for each module.  The module structure that these
    /// two entries refer to is described below.  This exists only in a dynamically linked shared
    /// library file.  For executable and object modules the file only contains one module so
    /// everything in the file belongs to the module.
    modtaboff: u32, // file offset to module table
    nmodtab: u32, // number of module table entries

    /// To support dynamic module binding the module structure for each module indicates the
    /// external references (defined and undefined) each module makes.  For each module there is an
    /// offset and a count into the reference symbol table for the symbols that the module
    /// references. This exists only in a dynamically linked shared library file.  For executable
    /// and object modules the defined external symbols and the undefined external symbols
    /// indicates the external references.
    extrefsymoff: u32, // offset to referenced symbol table
    nextrefsyms: u32, // number of referenced symbol table entries

    /// The sections that contain "symbol pointers" and "routine stubs" have indexes and (implied
    /// counts based on the size of the section and fixed size of the entry) into the "indirect
    /// symbol" table for each pointer and stub.  For every section of these two types the index
    /// into the indirect symbol table is stored in the section header in the field reserved1.  An
    /// indirect symbol table entry is simply a 32bit index into the symbol table to the symbol
    /// that the pointer or stub is referring to. The indirect symbol table is ordered to match the
    /// entries in the section.
    indirectsymoff: u32, // file offset to the indirect symbol table
    nindirectsyms: u32, // number of indirect symbol table entries

    /// To support relocating an individual module in a library file quickly the external
    /// relocation entries for each module in the library need to be accessed efficiently.  Since
    /// the relocation entries can't be accessed through the section headers for a library file
    /// they are separated into groups of local and external entries further grouped by module.  In
    /// this case the presents of this load command who's extreloff, nextrel, locreloff and nlocrel
    /// fields are non-zero indicates that the relocation entries of non-merged sections are not
    /// referenced through the section structures (and the reloff and nreloc fields in the section
    /// headers are set to zero).
    ///
    /// Since the relocation entries are not accessed through the section headers this requires the
    /// r_address field to be something other than a section offset to identify the item to be
    /// relocated.  In this case r_address is set to the offset from the vmaddr of the first
    /// LC_SEGMENT command. For MH_SPLIT_SEGS images r_address is set to the the offset from the
    /// vmaddr of the first read-write LC_SEGMENT command.
    ///
    /// The relocation entries are grouped by module and the module table entries have indexes and
    /// counts into them for the group of external relocation entries for that the module.
    ///
    /// For sections that are merged across modules there must not be any remaining external
    /// relocation entries for them (for merged sections remaining relocation entries must be
    /// local).
    extreloff: u32, // offset to external relocation entries
    nextrel: u32, // number of external relocation entries

    /// All the local relocation entries are grouped together (they are not grouped by their module
    /// since they are only used if the object is moved from it staticly link edited address).
    locreloff: u32, // offset to local relocation entries
    nlocrel: u32, // number of local relocation entries
}

/// A program that uses a dynamic linker contains a dylinker_command to identify the name of the
/// dynamic linker (LC_LOAD_DYLINKER). And a dynamic linker contains a dylinker_command to identify
/// the dynamic linker (LC_ID_DYLINKER). A file can have at most one of these.
///
/// This struct is also used for the LC_DYLD_ENVIRONMENT load command and contains string for dyld
/// to treat like environment variable.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct DylinkerCommand {
    cmd: Command, // LC_ID_DYLINKER, LC_LOAD_DYLINKER or LC_DYLD_ENVIRONMENT
    cmdsize: u32, // includes pathname string
    name: LcStr,  // dynamic linker's path name
}

/// The uuid load command contains a single 128-bit unique random number that
/// identifies an object produced by the static link editor.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct UuidCommand {
    cmd: Command,   // LC_UUID
    cmdsize: u32,   // sizeof(struct uuid_command)
    uuid: [u8; 16], // the 128-bit uuid
}

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum Platform {
    PLATFORM_MACOS = 1,
    PLATFORM_IOS = 2,
    PLATFORM_TVOS = 3,
    PLATFORM_WATCHOS = 4,
    PLATFORM_BRIDGEOS = 5,
    PLATFORM_MACCATALYST = 6,
    PLATFORM_IOSSIMULATOR = 7,
    PLATFORM_TVOSSIMULATOR = 8,
    PLATFORM_WATCHOSSIMULATOR = 9,
    PLATFORM_DRIVERKIT = 10,
    PLATFORM_FIRMWARE = 13,
    PLATFORM_SEPOS = 14,
}

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum Tools {
    TOOL_CLANG = 1,
    TOOL_SWIFT = 2,
    TOOL_LD = 3,
    TOOL_LLD = 4,
}

/// The build_version_command contains the min OS version on which this
/// binary was built to run for its platform.  The list of known platforms and
/// tool values following it.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct BuildVersionCommand {
    cmd: Command,       // LC_BUILD_VERSION
    cmdsize: u32, // sizeof(struct build_version_command) + ntools * sizeof(struct build_tool_version)
    platform: Platform, // platform
    minos: u32,   // X.Y.Z is encoded in nibbles xxxx.yy.zz
    sdk: u32,     // X.Y.Z is encoded in nibbles xxxx.yy.zz
    ntools: u32,  // number of tool entries following this
}

#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct BuildToolVersion {
    tool: Tools,  // enum for the tool
    version: u32, // version number of the tool
}

/// The source_version_command is an optional load command containing the version of the sources
/// used to build the binary.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct SourceVersionCommand {
    cmd: Command, // LC_SOURCE_VERSION
    cmdsize: u32, // 16
    version: u64, // A.B.C.D.E packed as a24.b10.c10.d10.e10
}

/// The entry_point_command is a replacement for thread_command.
/// It is used for main executables to specify the location (file offset)
/// of main().  If -stack_size was used at link time, the stacksize
/// field will contain the stack size need for the main thread.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct EntryPointCommand {
    cmd: Command,   // LC_MAIN only used in MH_EXECUTE filetypes */
    cmdsize: u32,   // 24 */
    entryoff: u64,  // file (__TEXT) offset of main() */
    stacksize: u64, // if not zero, initial stack size */
}

/// Dynamicly linked shared libraries are identified by two things. The pathname (the name of the
/// library as found for execution), and the compatibility version number. The pathname must match
/// and the compatibility number in the user of the library must be greater than or equal to the
/// library being used. The time stamp is used to record the time a library was built and copied
/// into user so it can be use to determined if the library used at runtime is exactly the same as
/// used to built the program.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct Dylib {
    name: LcStr,                // library's path name
    timestamp: u32,             // library's build time stamp
    current_version: u32,       // library's current version number
    compatibility_version: u32, // library's compatibility vers number
}

// A dynamically linked shared library (filetype == MH_DYLIB in the mach header) contains a
// dylib_command (cmd == LC_ID_DYLIB) to identify the library. An object that uses a dynamically
// linked shared library also contains a dylib_command (cmd == LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
// or LC_REEXPORT_DYLIB) for each library it uses.
#[derive(Packed, Debug, Copy, Clone)]
#[repr(packed)]
struct DylibCommand {
    cmd: Command, // LC_ID_DYLIB, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB
    cmdsize: u32, // includes pathname string
    dylib: Dylib, // the library identification
}

fn name(s: &str) -> [u8; 16] {
    let mut buf = [0; 16];
    for (i, b) in s.bytes().take(16).enumerate() {
        buf[i] = b;
    }
    buf
}

fn main() -> IOResult<()> {
    let cmdsize = size_of::<SegmentCommand64>() as u32;
    assert_eq!(cmdsize, 0x48, "Size should be 72 decimal 0x48");
    let command_page_zero = SegmentCommand64 {
        cmd: Command::LC_SEGMENT_64,
        cmdsize,
        segname: name("__PAGEZERO"),
        vmaddr: 0,
        vmsize: 0x0000000100000000,
        fileoff: 0,
        filesize: 0,
        maxprot: 0,
        initprot: 0,
        nsects: 0,
        flags: 0,
    };

    #[rustfmt::skip]
    let code = [
         0x20, 0x00, 0x80, 0xd2,
         0xe1, 0x00, 0x00, 0x10,
         0xa2, 0x01, 0x80, 0xd2,
         0x90, 0x00, 0x80, 0xd2,
         0x01, 0x00, 0x00, 0xd4,
         0x00, 0x00, 0x80, 0xd2,
         0x30, 0x00, 0x80, 0xd2,
         0x01, 0x00, 0x00, 0xd4,
         0x48, 0x65, 0x6c, 0x6c,
         0x6f, 0x20, 0x57, 0x6f,
         0x72, 0x6c, 0x64, 0x21,
         0x0a,
    ];
    let flags_for_instructions = (SectionFlags::S_ATTR_PURE_INSTRUCTIONS as u32)
        | (SectionFlags::S_ATTR_SOME_INSTRUCTIONS as u32);
    let section_text = Section64 {
        sectname: name("__text"),
        segname: name("__TEXT"),
        addr: 0x0000000100003f88,
        size: code.len() as u64,
        offset: 0x00003f88, // todo: compute this value
        align: 0x00000002,  // aligned at 4 (2 ** 2 = 4)
        reloff: 0x00000000,
        nreloc: 0x00000000,
        flags: flags_for_instructions,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
    };

    #[rustfmt::skip]
    let unwind_data = [
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x1c,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x1c,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x1c,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x88,
        0x3f, 0x00, 0x00, 0x34,
        0x00, 0x00, 0x00, 0x34,
        0x00, 0x00, 0x00, 0xb6,
        0x3f, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x34,
        0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x0c,
        0x00, 0x01, 0x00, 0x10,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let section_unwind = Section64 {
        sectname: name("__unwind_info"),
        segname: name("__TEXT"),
        addr: 0x0000000100003fb8,
        size: unwind_data.len() as u64,
        offset: 0x00003fb8, // todo: compute this value
        align: 0x00000002,
        reloff: 0x00000000,
        nreloc: 0x00000000,
        flags: 0,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
    };

    let sections = [section_text, section_unwind];
    let filesize = 0x0000000000004000;
    let read_execute =
        (SegmentCommandFlags::VM_PROT_READ as u32) | (SegmentCommandFlags::VM_PROT_EXECUTE as u32);

    let command_text = SegmentCommand64 {
        cmd: Command::LC_SEGMENT_64,
        cmdsize: size_of::<SegmentCommand64>() as u32
            + (sections.len() * size_of::<Section64>()) as u32,
        segname: name("__TEXT"),
        vmaddr: command_page_zero.vmaddr + command_page_zero.vmsize,
        vmsize: filesize,
        fileoff: 0,
        filesize,
        maxprot: read_execute,
        initprot: read_execute,
        nsects: sections.len() as u32,
        flags: 0,
    };

    #[rustfmt::skip]
    let link_edit = [
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x5f, 0x00,
        0x09, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x5f,
        0x6d, 0x68, 0x5f, 0x65,
        0x78, 0x65, 0x63, 0x75,
        0x74, 0x65, 0x5f, 0x68,
        0x65, 0x61, 0x64, 0x65,
        0x72, 0x00, 0x05, 0x73,
        0x74, 0x61, 0x72, 0x74,
        0x00, 0x26, 0x03, 0x00,
        0x88, 0x7f, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x88, 0x7f, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x1d, 0x00, 0x00, 0x00,
        0x0e, 0x01, 0x00, 0x00,
        0xa8, 0x3f, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x0f, 0x01, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x16, 0x00, 0x00, 0x00,
        0x0f, 0x01, 0x00, 0x00,
        0x88, 0x3f, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x5f, 0x5f,
        0x6d, 0x68, 0x5f, 0x65,
        0x78, 0x65, 0x63, 0x75,
        0x74, 0x65, 0x5f, 0x68,
        0x65, 0x61, 0x64, 0x65,
        0x72, 0x00, 0x5f, 0x73,
        0x74, 0x61, 0x72, 0x74,
        0x00, 0x73, 0x74, 0x72,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xfa, 0xde, 0x0c, 0xc0,
        0x00, 0x00, 0x01, 0x12,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x14,
        0xfa, 0xde, 0x0c, 0x02,
        0x00, 0x00, 0x00, 0xfe,
        0x00, 0x02, 0x04, 0x00,
        0x00, 0x02, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x5e,
        0x00, 0x00, 0x00, 0x58,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05,
        0x00, 0x00, 0x40, 0xd0,
        0x20, 0x02, 0x00, 0x0c,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x68, 0x65, 0x6c, 0x6c,
        0x6f, 0x00, 0x93, 0xdf,
        0x57, 0xa6, 0x16, 0x4d,
        0xf4, 0x1a, 0x5e, 0x58,
        0xcd, 0x35, 0xe4, 0xa3,
        0x9b, 0xf3, 0xc5, 0x99,
        0x2a, 0x1a, 0xdb, 0x2b,
        0x7c, 0xe5, 0x26, 0x33,
        0xda, 0xd5, 0x96, 0x27,
        0xfe, 0x45, 0xad, 0x7f,
        0xac, 0xb2, 0x58, 0x6f,
        0xc6, 0xe9, 0x66, 0xc0,
        0x04, 0xd7, 0xd1, 0xd1,
        0x6b, 0x02, 0x4f, 0x58,
        0x05, 0xff, 0x7c, 0xb4,
        0x7c, 0x7a, 0x85, 0xda,
        0xbd, 0x8b, 0x48, 0x89,
        0x2c, 0xa7, 0xad, 0x7f,
        0xac, 0xb2, 0x58, 0x6f,
        0xc6, 0xe9, 0x66, 0xc0,
        0x04, 0xd7, 0xd1, 0xd1,
        0x6b, 0x02, 0x4f, 0x58,
        0x05, 0xff, 0x7c, 0xb4,
        0x7c, 0x7a, 0x85, 0xda,
        0xbd, 0x8b, 0x48, 0x89,
        0x2c, 0xa7, 0xb5, 0x90,
        0xde, 0x41, 0xa6, 0x48,
        0xb3, 0xf5, 0xaf, 0x00,
        0x6d, 0x70, 0xa6, 0x54,
        0x45, 0x0b, 0x8c, 0x45,
        0xe8, 0x89, 0x64, 0x0a,
        0x24, 0xbf, 0xa0, 0x20,
        0x49, 0xb8, 0x1c, 0x10,
        0x94, 0x13, 0x11, 0x8e,
        0x6b, 0x52, 0x40, 0xfb,
        0xe9, 0xe0, 0xfe, 0xec,
        0x79, 0x09, 0xec, 0xa4,
        0xe6, 0x2c, 0x17, 0xf4,
        0xd3, 0x13, 0x79, 0x1f,
        0x84, 0x8f, 0xae, 0x67,
        0x34, 0xc8, 0x8d, 0x77,
        0xd7, 0x8b,
    ];
    assert_eq!(link_edit.len(), 0x01e2, "link edit length must be 0x0x01e2");
    let read = SegmentCommandFlags::VM_PROT_READ as u32;
    let command_link_edit = SegmentCommand64 {
        cmd: Command::LC_SEGMENT_64,
        cmdsize: size_of::<SegmentCommand64>() as u32,
        segname: name("__LINKEDIT"),
        vmaddr: 0x0000000100004000,
        vmsize: 0x0000000000004000,
        fileoff: 0x0000000000004000,
        filesize: link_edit.len() as u64,
        maxprot: read,
        initprot: read,
        nsects: 0,
        flags: 0,
    };

    let command_chained_fixups = LinkEditDataCommand {
        cmd: Command::LC_DYLD_CHAINED_FIXUPS,
        cmdsize: size_of::<LinkEditDataCommand>() as u32,
        dataoff: 0x00004000,
        datasize: 0x00000038,
    };

    let command_exports_trie = LinkEditDataCommand {
        cmd: Command::LC_DYLD_EXPORTS_TRIE,
        cmdsize: size_of::<LinkEditDataCommand>() as u32,
        dataoff: 0x00004038,
        datasize: 0x30,
    };

    let command_symtab = SymtabCommand {
        cmd: Command::LC_SYMTAB,
        cmdsize: size_of::<SymtabCommand>() as u32,
        symoff: 0x00004070,
        nsyms: 0x00000003,
        stroff: 0x000040a0,
        strsize: 0x00000028, // string table size in bytes
    };

    let command_dymtab = DysymtabCommand {
        cmd: Command::LC_DYSYMTAB,
        cmdsize: size_of::<DysymtabCommand>() as u32,
        ilocalsym: 0x00000000,
        nlocalsym: 0x00000001,
        iextdefsym: 0x00000001,
        nextdefsym: 0x00000002,
        iundefsym: 0x00000003,
        nundefsym: 0x00000000,
        tocoff: 0x00000000,
        ntoc: 0x00000000,
        modtaboff: 0x00000000,
        nmodtab: 0x00000000,
        extrefsymoff: 0x00000000,
        nextrefsyms: 0x00000000,
        indirectsymoff: 0x00000000,
        nindirectsyms: 0x00000000,
        extreloff: 0x00000000,
        nextrel: 0x00000000,
        locreloff: 0x00000000,
        nlocrel: 0x00000000,
    };

    let linker_path = "/usr/lib/dyld\x00\x00\x00\x00\x00\x00\x00";
    let command_dylinker = DylinkerCommand {
        cmd: Command::LC_LOAD_DYLINKER,
        cmdsize: 0x00000020,              // includes pathname string
        name: LcStr::Offset(0x0c as u32), // dynamic linker's path name
    };

    #[rustfmt::skip]
    let uuid = [
        0xd6, 0xac, 0xb6, 0x47,
        0x0d, 0xb6, 0x3a, 0xbd,
        0x9f, 0x33, 0x1d, 0x0b,
        0xc6, 0x9a, 0x99, 0x4e,
    ];
    let command_uuid = UuidCommand {
        cmd: Command::LC_UUID,
        cmdsize: size_of::<UuidCommand>() as u32,
        uuid,
    };
    let build_tool_versions = [BuildToolVersion {
        tool: Tools::TOOL_LD,
        version: 0x03340100,
    }];
    let command_build = BuildVersionCommand {
        cmd: Command::LC_BUILD_VERSION,
        cmdsize: (size_of::<BuildVersionCommand>()
            + build_tool_versions.len() * size_of::<BuildToolVersion>()) as u32,
        platform: Platform::PLATFORM_MACOS,
        minos: 0x000d0000,
        sdk: 0x000d0100,
        ntools: 0x00000001,
    };
    let command_source_version = SourceVersionCommand {
        cmd: Command::LC_SOURCE_VERSION,
        cmdsize: size_of::<SourceVersionCommand>() as u32,
        version: 0x0,
    };
    let command_entry = EntryPointCommand {
        cmd: Command::LC_MAIN,
        cmdsize: size_of::<EntryPointCommand>() as u32,
        entryoff: 0x0000000000003f88,
        stacksize: 0x0000000000000000,
    };

    let clib_path = "/usr/lib/libSystem.B.dylib\x00\x00\x00\x00\x00\x00";
    let dylib = Dylib {
        name: LcStr::Offset(0x18 as u32),
        timestamp: 0x00000002,
        current_version: 0x05270000,
        compatibility_version: 0x00010000,
    };
    let command_dylib = DylibCommand {
        cmd: Command::LC_LOAD_DYLIB,
        cmdsize: 0x38,
        dylib,
    };
    let command_function_starts = LinkEditDataCommand {
        cmd: Command::LC_FUNCTION_STARTS,
        cmdsize: size_of::<LinkEditDataCommand>() as u32,
        dataoff: 0x00004068,
        datasize: 0x00000008,
    };
    let command_data_in_code = LinkEditDataCommand {
        cmd: Command::LC_DATA_IN_CODE,
        cmdsize: size_of::<LinkEditDataCommand>() as u32,
        dataoff: 0x00004070,
        datasize: 0x00000000,
    };
    let command_code_signature = LinkEditDataCommand {
        cmd: Command::LC_CODE_SIGNATURE,
        cmdsize: size_of::<LinkEditDataCommand>() as u32,
        dataoff: 0x000040d0,
        datasize: 0x00000112,
    };

    let header = Header64 {
        magic: Magic64::MH_MAGIC_64,
        cputtype: CpuType::CPU_TYPE_ARM64,
        cpusubtype: CpuSubtype::CPU_SUBTYPE_ARM64_ALL,
        filetype: FileType::MH_EXECUTE,
        ncmds: 16u32,
        sizeofcmds: 0x2e8,
        flags: (HeaderFlags::MH_PIE as u32)
            | (HeaderFlags::MH_TWOLEVEL as u32)
            | (HeaderFlags::MH_DYLDLINK as u32)
            | (HeaderFlags::MH_NOUNDEFS as u32),
        reserved: 0u32,
    };

    let filename = args().nth(1).expect("File name is required");
    let mut file = File::create(filename)?;
    file.write(header.to_bytes())?;
    file.write(command_page_zero.to_bytes())?;
    file.write(command_text.to_bytes())?;
    file.write(section_text.to_bytes())?;
    file.write(section_unwind.to_bytes())?;
    file.write(command_link_edit.to_bytes())?;
    file.write(command_chained_fixups.to_bytes())?;
    file.write(command_exports_trie.to_bytes())?;
    file.write(command_symtab.to_bytes())?;
    file.write(command_dymtab.to_bytes())?;
    file.write(command_dylinker.to_bytes())?;
    file.write(linker_path.as_bytes())?;
    file.write(command_uuid.to_bytes())?;
    file.write(command_build.to_bytes())?;
    file.write(build_tool_versions[0].to_bytes())?;
    file.write(command_source_version.to_bytes())?;
    file.write(command_entry.to_bytes())?;
    file.write(command_dylib.to_bytes())?;
    file.write(clib_path.as_bytes())?;
    file.write(command_function_starts.to_bytes())?;
    file.write(command_data_in_code.to_bytes())?;
    file.write(command_code_signature.to_bytes())?;

    file.set_len(0x00003f88)?;
    file.seek(SeekFrom::Start(0x00003f88))?;
    file.write(&code)?;
    file.write(&unwind_data)?;
    file.write(&[0x00, 0x00, 0x00])?;
    file.write(&link_edit)?;

    Ok(())
}
