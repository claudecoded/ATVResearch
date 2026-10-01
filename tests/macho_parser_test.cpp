#include "atvresearch/macho/macho_parser.hpp"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {

void writeU32(
    std::vector<std::uint8_t>& data,
    std::size_t offset,
    std::uint32_t value
) {
    data[offset] =
        static_cast<std::uint8_t>(
            value & 0xff
        );

    data[offset + 1] =
        static_cast<std::uint8_t>(
            (value >> 8) & 0xff
        );

    data[offset + 2] =
        static_cast<std::uint8_t>(
            (value >> 16) & 0xff
        );

    data[offset + 3] =
        static_cast<std::uint8_t>(
            (value >> 24) & 0xff
        );
}

} // namespace

int main() {
    const auto path =
        std::filesystem::temp_directory_path() /
        "atvresearch_macho_test.bin";

    std::vector<std::uint8_t> data(
        32,
        0
    );

    // 64-bit Mach-O magic.
    writeU32(
        data,
        0,
        0xfeedfacf
    );

    // ARM64.
    writeU32(
        data,
        4,
        0x0100000c
    );

    // CPU subtype.
    writeU32(
        data,
        8,
        0
    );

    // MH_EXECUTE.
    writeU32(
        data,
        12,
        2
    );

    // Number of load commands.
    writeU32(
        data,
        16,
        0
    );

    // Load command size.
    writeU32(
        data,
        20,
        0
    );

    // Flags.
    writeU32(
        data,
        24,
        0
    );

    // Reserved.
    writeU32(
        data,
        28,
        0
    );

    {
        std::ofstream file(
            path,
            std::ios::binary
        );

        file.write(
            reinterpret_cast<const char*>(
                data.data()
            ),
            static_cast<std::streamsize>(
                data.size()
            )
        );
    }

    assert(
        atvresearch::macho::MachOParser::
            isMachO(path)
    );

    const auto result =
        atvresearch::macho::MachOParser::
            parse(path);

    assert(result.valid);
    assert(!result.universal);
    assert(result.images.size() == 1);

    const auto& image =
        result.images.front();

    assert(image.is64Bit);
    assert(!image.bigEndian);

    assert(
        image.header.cpuType ==
        0x0100000c
    );

    assert(
        image.header.fileType == 2
    );

    assert(
        atvresearch::macho::MachOParser::
            cpuTypeName(
                image.header.cpuType
            ) == "arm64"
    );

    std::filesystem::remove(path);

    return 0;
}
