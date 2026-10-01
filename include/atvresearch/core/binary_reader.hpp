#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace atvresearch {

class BinaryReader {
public:
    explicit BinaryReader(
        const std::filesystem::path& path
    );

    bool valid() const noexcept;

    std::size_t size() const noexcept;

    bool canRead(
        std::size_t offset,
        std::size_t length
    ) const noexcept;

    std::uint8_t readU8(
        std::size_t offset
    ) const;

    std::uint16_t readU16(
        std::size_t offset,
        bool bigEndian = false
    ) const;

    std::uint32_t readU32(
        std::size_t offset,
        bool bigEndian = false
    ) const;

    std::uint64_t readU64(
        std::size_t offset,
        bool bigEndian = false
    ) const;

    std::string readString(
        std::size_t offset,
        std::size_t length
    ) const;

    std::vector<std::uint8_t> readBytes(
        std::size_t offset,
        std::size_t length
    ) const;

private:
    std::vector<std::uint8_t> data_;
};

} // namespace atvresearch
