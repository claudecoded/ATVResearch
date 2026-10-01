#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace atvresearch::macho {

struct Architecture {
    std::uint32_t cpuType = 0;
    std::uint32_t cpuSubtype = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t alignment = 0;
};

struct MachHeader {
    std::uint32_t magic = 0;
    std::uint32_t cpuType = 0;
    std::uint32_t cpuSubtype = 0;
    std::uint32_t fileType = 0;
    std::uint32_t commandCount = 0;
    std::uint32_t commandSize = 0;
    std::uint32_t flags = 0;
    std::uint32_t reserved = 0;
};

struct Segment {
    std::string name;

    std::uint64_t virtualAddress = 0;
    std::uint64_t virtualSize = 0;
    std::uint64_t fileOffset = 0;
    std::uint64_t fileSize = 0;

    std::uint32_t maxProtection = 0;
    std::uint32_t initialProtection = 0;
    std::uint32_t sectionCount = 0;
    std::uint32_t flags = 0;
};

struct LoadCommand {
    std::uint32_t command = 0;
    std::uint32_t size = 0;
    std::string name;
};

struct MachOImage {
    std::size_t fileOffset = 0;

    bool is64Bit = false;
    bool bigEndian = false;

    MachHeader header;

    std::vector<Segment> segments;
    std::vector<LoadCommand> loadCommands;
};

struct MachOFile {
    bool valid = false;
    bool universal = false;

    std::vector<Architecture> architectures;
    std::vector<MachOImage> images;
};

class MachOParser {
public:
    static MachOFile parse(
        const std::filesystem::path& path
    );

    static bool isMachO(
        const std::filesystem::path& path
    );

    static std::string cpuTypeName(
        std::uint32_t cpuType
    );

    static std::string fileTypeName(
        std::uint32_t fileType
    );

    static std::string loadCommandName(
        std::uint32_t command
    );
};

} // namespace atvresearch::macho
