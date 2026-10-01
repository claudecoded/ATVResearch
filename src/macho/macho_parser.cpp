#include "atvresearch/macho/macho_parser.hpp"

#include "atvresearch/core/binary_reader.hpp"

#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace atvresearch::macho {

namespace {

constexpr std::uint32_t MH_MAGIC = 0xfeedface;
constexpr std::uint32_t MH_CIGAM = 0xcefaedfe;
constexpr std::uint32_t MH_MAGIC_64 = 0xfeedfacf;
constexpr std::uint32_t MH_CIGAM_64 = 0xcffaedfe;

constexpr std::uint32_t FAT_MAGIC = 0xcafebabe;
constexpr std::uint32_t FAT_CIGAM = 0xbebafeca;

constexpr std::uint32_t CPU_TYPE_X86 = 7;
constexpr std::uint32_t CPU_TYPE_X86_64 = 0x01000007;
constexpr std::uint32_t CPU_TYPE_ARM = 12;
constexpr std::uint32_t CPU_TYPE_ARM64 = 0x0100000c;

constexpr std::uint32_t LC_SEGMENT = 0x1;
constexpr std::uint32_t LC_SYMTAB = 0x2;
constexpr std::uint32_t LC_DYSYMTAB = 0xb;
constexpr std::uint32_t LC_LOAD_DYLIB = 0xc;
constexpr std::uint32_t LC_ID_DYLIB = 0xd;
constexpr std::uint32_t LC_LOAD_WEAK_DYLIB = 0x18;
constexpr std::uint32_t LC_SEGMENT_64 = 0x19;
constexpr std::uint32_t LC_UUID = 0x1b;
constexpr std::uint32_t LC_RPATH = 0x1c;
constexpr std::uint32_t LC_CODE_SIGNATURE = 0x1d;
constexpr std::uint32_t LC_MAIN = 0x80000028;

MachOImage parseImage(
    const atvresearch::BinaryReader& reader,
    std::size_t offset,
    bool bigEndian,
    bool is64Bit
) {
    const std::size_t headerSize =
        is64Bit ? 32 : 28;

    if (!reader.canRead(offset, headerSize)) {
        throw std::runtime_error(
            "Truncated Mach-O header"
        );
    }

    MachOImage image;

    image.fileOffset = offset;
    image.bigEndian = bigEndian;
    image.is64Bit = is64Bit;

    image.header.magic =
        reader.readU32(offset, bigEndian);

    image.header.cpuType =
        reader.readU32(offset + 4, bigEndian);

    image.header.cpuSubtype =
        reader.readU32(offset + 8, bigEndian);

    image.header.fileType =
        reader.readU32(offset + 12, bigEndian);

    image.header.commandCount =
        reader.readU32(offset + 16, bigEndian);

    image.header.commandSize =
        reader.readU32(offset + 20, bigEndian);

    image.header.flags =
        reader.readU32(offset + 24, bigEndian);

    if (is64Bit) {
        image.header.reserved =
            reader.readU32(offset + 28, bigEndian);
    }

    const std::size_t commandsOffset =
        offset + headerSize;

    if (!reader.canRead(
            commandsOffset,
            image.header.commandSize)) {
        throw std::runtime_error(
            "Truncated Mach-O load command area"
        );
    }

    std::size_t commandOffset =
        commandsOffset;

    for (std::uint32_t index = 0;
         index < image.header.commandCount;
         ++index) {

        if (!reader.canRead(commandOffset, 8)) {
            throw std::runtime_error(
                "Truncated Mach-O load command"
            );
        }

        const std::uint32_t command =
            reader.readU32(
                commandOffset,
                bigEndian
            );

        const std::uint32_t commandSize =
            reader.readU32(
                commandOffset + 4,
                bigEndian
            );

        if (commandSize < 8) {
            throw std::runtime_error(
                "Invalid Mach-O load command size"
            );
        }

        if (!reader.canRead(
                commandOffset,
                commandSize)) {
            throw std::runtime_error(
                "Load command exceeds file size"
            );
        }

        LoadCommand loadCommand;

        loadCommand.command = command;
        loadCommand.size = commandSize;
        loadCommand.name =
            MachOParser::loadCommandName(command);

        image.loadCommands.push_back(
            loadCommand
        );

        if (command == LC_SEGMENT_64 &&
            commandSize >= 72) {

            Segment segment;

            segment.name =
                reader.readString(
                    commandOffset + 8,
                    16
                );

            segment.virtualAddress =
                reader.readU64(
                    commandOffset + 24,
                    bigEndian
                );

            segment.virtualSize =
                reader.readU64(
                    commandOffset + 32,
                    bigEndian
                );

            segment.fileOffset =
                reader.readU64(
                    commandOffset + 40,
                    bigEndian
                );

            segment.fileSize =
                reader.readU64(
                    commandOffset + 48,
                    bigEndian
                );

            segment.maxProtection =
                reader.readU32(
                    commandOffset + 56,
                    bigEndian
                );

            segment.initialProtection =
                reader.readU32(
                    commandOffset + 60,
                    bigEndian
                );

            segment.sectionCount =
                reader.readU32(
                    commandOffset + 64,
                    bigEndian
                );

            segment.flags =
                reader.readU32(
                    commandOffset + 68,
                    bigEndian
                );

            image.segments.push_back(
                segment
            );
        }

        commandOffset += commandSize;
    }

    return image;
}

bool parseMagic(
    std::uint32_t magic,
    bool& is64Bit,
    bool& bigEndian
) {
    switch (magic) {
        case MH_MAGIC:
            is64Bit = false;
            bigEndian = false;
            return true;

        case MH_CIGAM:
            is64Bit = false;
            bigEndian = true;
            return true;

        case MH_MAGIC_64:
            is64Bit = true;
            bigEndian = false;
            return true;

        case MH_CIGAM_64:
            is64Bit = true;
            bigEndian = true;
            return true;

        default:
            return false;
    }
}

} // namespace

MachOFile MachOParser::parse(
    const std::filesystem::path& path
) {
    atvresearch::BinaryReader reader(path);

    if (!reader.valid() || reader.size() < 4) {
        throw std::runtime_error(
            "Unable to read input file"
        );
    }

    MachOFile result;

    const std::uint32_t magic =
        reader.readU32(0, false);

    if (magic == FAT_MAGIC ||
        magic == FAT_CIGAM) {

        result.universal = true;

        const bool bigEndian =
            magic == FAT_MAGIC;

        const std::uint32_t architectureCount =
            reader.readU32(4, bigEndian);

        constexpr std::size_t FAT_ARCH_SIZE = 20;

        if (architectureCount > 128) {
            throw std::runtime_error(
                "Invalid FAT architecture count"
            );
        }

        const std::size_t tableSize =
            static_cast<std::size_t>(
                architectureCount
            ) * FAT_ARCH_SIZE;

        if (!reader.canRead(8, tableSize)) {
            throw std::runtime_error(
                "Truncated FAT architecture table"
            );
        }

        for (std::uint32_t index = 0;
             index < architectureCount;
             ++index) {

            const std::size_t entryOffset =
                8 +
                static_cast<std::size_t>(index) *
                    FAT_ARCH_SIZE;

            Architecture architecture;

            architecture.cpuType =
                reader.readU32(
                    entryOffset,
                    bigEndian
                );

            architecture.cpuSubtype =
                reader.readU32(
                    entryOffset + 4,
                    bigEndian
                );

            architecture.offset =
                reader.readU32(
                    entryOffset + 8,
                    bigEndian
                );

            architecture.size =
                reader.readU32(
                    entryOffset + 12,
                    bigEndian
                );

            architecture.alignment =
                reader.readU32(
                    entryOffset + 16,
                    bigEndian
                );

            result.architectures.push_back(
                architecture
            );

            if (architecture.offset >= reader.size()) {
                throw std::runtime_error(
                    "FAT architecture points outside file"
                );
            }

            bool image64 = false;
            bool imageBigEndian = false;

            const auto imageMagic =
                reader.readU32(
                    static_cast<std::size_t>(
                        architecture.offset
                    ),
                    false
                );

            if (!parseMagic(
                    imageMagic,
                    image64,
                    imageBigEndian)) {
                continue;
            }

            result.images.push_back(
                parseImage(
                    reader,
                    static_cast<std::size_t>(
                        architecture.offset
                    ),
                    imageBigEndian,
                    image64
                )
            );
        }

        result.valid =
            !result.images.empty();

        return result;
    }

    bool is64Bit = false;
    bool bigEndian = false;

    if (!parseMagic(
            magic,
            is64Bit,
            bigEndian)) {
        throw std::runtime_error(
            "Input is not a supported Mach-O file"
        );
    }

    result.images.push_back(
        parseImage(
            reader,
            0,
            bigEndian,
            is64Bit
        )
    );

    result.valid = true;

    return result;
}

bool MachOParser::isMachO(
    const std::filesystem::path& path
) {
    try {
        atvresearch::BinaryReader reader(path);

        if (!reader.valid() ||
            reader.size() < 4) {
            return false;
        }

        const auto magic =
            reader.readU32(0, false);

        bool is64Bit = false;
        bool bigEndian = false;

        if (parseMagic(
                magic,
                is64Bit,
                bigEndian)) {
            return true;
        }

        return magic == FAT_MAGIC ||
               magic == FAT_CIGAM;
    }
    catch (...) {
        return false;
    }
}

std::string MachOParser::cpuTypeName(
    std::uint32_t cpuType
) {
    switch (cpuType) {
        case CPU_TYPE_X86:
            return "x86";

        case CPU_TYPE_X86_64:
            return "x86_64";

        case CPU_TYPE_ARM:
            return "arm";

        case CPU_TYPE_ARM64:
            return "arm64";

        default: {
            std::ostringstream stream;

            stream
                << "unknown(0x"
                << std::hex
                << cpuType
                << ")";

            return stream.str();
        }
    }
}

std::string MachOParser::fileTypeName(
    std::uint32_t fileType
) {
    switch (fileType) {
        case 1:
            return "relocatable object";

        case 2:
            return "executable";

        case 3:
            return "fixed VM shared library";

        case 4:
            return "core";

        case 5:
            return "preloaded executable";

        case 6:
            return "dynamic library";

        case 7:
            return "dynamic linker";

        case 8:
            return "dynamic library stub";

        case 9:
            return "dSYM companion";

        case 10:
            return "kext bundle";

        default:
            return "unknown";
    }
}

std::string MachOParser::loadCommandName(
    std::uint32_t command
) {
    switch (command) {
        case LC_SEGMENT:
            return "LC_SEGMENT";

        case LC_SYMTAB:
            return "LC_SYMTAB";

        case LC_DYSYMTAB:
            return "LC_DYSYMTAB";

        case LC_LOAD_DYLIB:
            return "LC_LOAD_DYLIB";

        case LC_ID_DYLIB:
            return "LC_ID_DYLIB";

        case LC_LOAD_WEAK_DYLIB:
            return "LC_LOAD_WEAK_DYLIB";

        case LC_SEGMENT_64:
            return "LC_SEGMENT_64";

        case LC_UUID:
            return "LC_UUID";

        case LC_RPATH:
            return "LC_RPATH";

        case LC_CODE_SIGNATURE:
            return "LC_CODE_SIGNATURE";

        case LC_MAIN:
            return "LC_MAIN";

        default: {
            std::ostringstream stream;

            stream
                << "UNKNOWN(0x"
                << std::hex
                << command
                << ")";

            return stream.str();
        }
    }
}

} // namespace atvresearch::macho
