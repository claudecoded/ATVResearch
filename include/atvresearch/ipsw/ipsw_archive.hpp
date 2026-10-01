#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace atvresearch::ipsw {

struct ArchiveEntry {
    std::string path;
    std::uint64_t size = 0;
    bool directory = false;
};

struct ArchiveInfo {
    std::uint64_t entryCount = 0;
    std::uint64_t totalSize = 0;

    std::vector<ArchiveEntry> entries;
};

class IPSWArchive {
public:
    static ArchiveInfo inspect(
        const std::filesystem::path& path
    );

    static std::vector<ArchiveEntry> list(
        const std::filesystem::path& path
    );

    static void extract(
        const std::filesystem::path& path,
        const std::filesystem::path& outputDirectory
    );
};

} // namespace atvresearch::ipsw
