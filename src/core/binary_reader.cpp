#include "atvresearch/core/binary_reader.hpp"

#include <fstream>
#include <stdexcept>

namespace atvresearch {

BinaryReader::BinaryReader(
    const std::filesystem::path& path
) {
    std::ifstream file(
        path,
        std::ios::binary | std::ios::ate
    );

    if (!file) {
        return;
    }

    const auto end = file.tellg();

    if (end <= 0) {
        return;
    }

    data_.resize(
        static_cast<std::size_t>(end)
    );

    file.seekg(0, std::ios::beg);

    file.read(
        reinterpret_cast<char*>(data_.data()),
        static_cast<std::streamsize>(data_.size())
    );

    if (!file) {
        data_.clear();
    }
}

bool BinaryReader::valid() const noexcept {
    return !data_.empty();
}

std::size_t BinaryReader::size() const noexcept {
    return data_.size();
}

bool BinaryReader::canRead(
    std::size_t offset,
    std::size_t length
) const noexcept {
    if (offset > data_.size()) {
        return false;
    }

    return length <= data_.size() - offset;
}

std::uint8_t BinaryReader::readU8(
    std::size_t offset
) const {
    if (!canRead(offset, 1)) {
        throw std::out_of_range(
            "Binary read exceeds file size"
        );
    }

    return data_[offset];
}

std::uint16_t BinaryReader::readU16(
    std::size_t offset,
    bool bigEndian
) const {
    if (!canRead(offset, 2)) {
        throw std::out_of_range(
            "Binary read exceeds file size"
        );
    }

    if (bigEndian) {
        return
            (static_cast<std::uint16_t>(data_[offset]) << 8) |
            static_cast<std::uint16_t>(data_[offset + 1]);
    }

    return
        static_cast<std::uint16_t>(data_[offset]) |
        (static_cast<std::uint16_t>(data_[offset + 1]) << 8);
}

std::uint32_t BinaryReader::readU32(
    std::size_t offset,
    bool bigEndian
) const {
    if (!canRead(offset, 4)) {
        throw std::out_of_range(
            "Binary read exceeds file size"
        );
    }

    if (bigEndian) {
        return
            (static_cast<std::uint32_t>(data_[offset]) << 24) |
            (static_cast<std::uint32_t>(data_[offset + 1]) << 16) |
            (static_cast<std::uint32_t>(data_[offset + 2]) << 8) |
            static_cast<std::uint32_t>(data_[offset + 3]);
    }

    return
        static_cast<std::uint32_t>(data_[offset]) |
        (static_cast<std::uint32_t>(data_[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(data_[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(data_[offset + 3]) << 24);
}

std::uint64_t BinaryReader::readU64(
    std::size_t offset,
    bool bigEndian
) const {
    if (!canRead(offset, 8)) {
        throw std::out_of_range(
            "Binary read exceeds file size"
        );
    }

    std::uint64_t value = 0;

    if (bigEndian) {
        for (std::size_t i = 0; i < 8; ++i) {
            value =
                (value << 8) |
                static_cast<std::uint64_t>(
                    data_[offset + i]
                );
        }
    } else {
        for (std::size_t i = 0; i < 8; ++i) {
            value |=
                static_cast<std::uint64_t>(
                    data_[offset + i]
                ) << (i * 8);
        }
    }

    return value;
}

std::string BinaryReader::readString(
    std::size_t offset,
    std::size_t length
) const {
    if (!canRead(offset, length)) {
        throw std::out_of_range(
            "String read exceeds file size"
        );
    }

    std::string result;

    for (std::size_t i = 0; i < length; ++i) {
        const char character =
            static_cast<char>(data_[offset + i]);

        if (character == '\0') {
            break;
        }

        result.push_back(character);
    }

    return result;
}

std::vector<std::uint8_t> BinaryReader::readBytes(
    std::size_t offset,
    std::size_t length
) const {
    if (!canRead(offset, length)) {
        throw std::out_of_range(
            "Byte read exceeds file size"
        );
    }

    return {
        data_.begin() +
            static_cast<std::ptrdiff_t>(offset),

        data_.begin() +
            static_cast<std::ptrdiff_t>(offset + length)
    };
}

} // namespace atvresearch
