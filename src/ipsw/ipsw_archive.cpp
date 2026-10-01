#include "atvresearch/ipsw/ipsw_archive.hpp"

#include <archive.h>
#include <archive_entry.h>

#include <fstream>
#include <stdexcept>
#include <vector>

namespace atvresearch::ipsw {

namespace {

class ArchiveReader {
public:
    explicit ArchiveReader(
        const std::filesystem::path& path
    ) {
        archive_ = archive_read_new();

        if (!archive_) {
            throw std::runtime_error(
                "Unable to create archive reader"
            );
        }

        archive_read_support_filter_all(
            archive_
        );

        archive_read_support_format_all(
            archive_
        );

        const int result =
            archive_read_open_filename(
                archive_,
                path.string().c_str(),
                10240
            );

        if (result != ARCHIVE_OK) {
            const char* error =
                archive_error_string(archive_);

            archive_read_free(archive_);
            archive_ = nullptr;

            throw std::runtime_error(
                "Unable to open archive: " +
                std::string(
                    error ? error : "unknown error"
                )
            );
        }
    }

    ~ArchiveReader() {
        if (archive_) {
            archive_read_free(archive_);
        }
    }

    ArchiveReader(const ArchiveReader&) = delete;
    ArchiveReader& operator=(
        const ArchiveReader&
    ) = delete;

    archive* get() const {
        return archive_;
    }

private:
    archive* archive_ = nullptr;
};

bool isSafePath(
    const std::filesystem::path& path
) {
    if (path.is_absolute()) {
        return false;
    }

    for (const auto& component : path) {
        if (component == "..") {
            return false;
        }
    }

    return true;
}

} // namespace

std::vector<ArchiveEntry> IPSWArchive::list(
    const std::filesystem::path& path
) {
    ArchiveReader reader(path);

    std::vector<ArchiveEntry> entries;

    archive_entry* entry = nullptr;

    while (true) {
        const int result =
            archive_read_next_header(
                reader.get(),
                &entry
            );

        if (result == ARCHIVE_EOF) {
            break;
        }

        if (result != ARCHIVE_OK) {
            const char* error =
                archive_error_string(
                    reader.get()
                );

            throw std::runtime_error(
                "Unable to read archive: " +
                std::string(
                    error ? error : "unknown error"
                )
            );
        }

        ArchiveEntry item;

        const char* name =
            archive_entry_pathname(entry);

        if (name) {
            item.path = name;
        }

        const auto size =
            archive_entry_size(entry);

        if (size > 0) {
            item.size =
                static_cast<std::uint64_t>(size);
        }

        item.directory =
            archive_entry_filetype(entry) ==
            AE_IFDIR;

        entries.push_back(
            std::move(item)
        );

        archive_read_data_skip(
            reader.get()
        );
    }

    return entries;
}

ArchiveInfo IPSWArchive::inspect(
    const std::filesystem::path& path
) {
    ArchiveInfo info;

    info.entries = list(path);

    info.entryCount =
        static_cast<std::uint64_t>(
            info.entries.size()
        );

    for (const auto& entry :
         info.entries) {

        info.totalSize += entry.size;
    }

    return info;
}

void IPSWArchive::extract(
    const std::filesystem::path& path,
    const std::filesystem::path& outputDirectory
) {
    std::filesystem::create_directories(
        outputDirectory
    );

    const auto base =
        std::filesystem::absolute(
            outputDirectory
        ).lexically_normal();

    ArchiveReader reader(path);

    archive_entry* entry = nullptr;

    while (true) {
        const int result =
            archive_read_next_header(
                reader.get(),
                &entry
            );

        if (result == ARCHIVE_EOF) {
            break;
        }

        if (result != ARCHIVE_OK) {
            const char* error =
                archive_error_string(
                    reader.get()
                );

            throw std::runtime_error(
                "Unable to read archive: " +
                std::string(
                    error ? error : "unknown error"
                )
            );
        }

        const char* rawName =
            archive_entry_pathname(entry);

        if (!rawName) {
            archive_read_data_skip(
                reader.get()
            );

            continue;
        }

        const std::filesystem::path relativePath(
            rawName
        );

        if (!isSafePath(relativePath)) {
            throw std::runtime_error(
                "Unsafe archive path: " +
                relativePath.string()
            );
        }

        const auto destination =
            (base / relativePath).lexically_normal();

        const auto relativeToBase =
            std::filesystem::relative(
                destination,
                base
            );

        if (!relativeToBase.empty() &&
            relativeToBase.string() == "..") {
            throw std::runtime_error(
                "Archive path escapes output directory"
            );
        }

        if (archive_entry_filetype(entry) ==
            AE_IFDIR) {

            std::filesystem::create_directories(
                destination
            );

            continue;
        }

        std::filesystem::create_directories(
            destination.parent_path()
        );

        std::ofstream output(
            destination,
            std::ios::binary
        );

        if (!output) {
            throw std::runtime_error(
                "Unable to create output file: " +
                destination.string()
            );
        }

        std::vector<char> buffer(
            64 * 1024
        );

        while (true) {
            const auto bytes =
                archive_read_data(
                    reader.get(),
                    buffer.data(),
                    buffer.size()
                );

            if (bytes == 0) {
                break;
            }

            if (bytes < 0) {
                const char* error =
                    archive_error_string(
                        reader.get()
                    );

                throw std::runtime_error(
                    "Extraction failed: " +
                    std::string(
                        error ? error : "unknown error"
                    )
                );
            }

            output.write(
                buffer.data(),
                bytes
            );

            if (!output) {
                throw std::runtime_error(
                    "Failed writing: " +
                    destination.string()
                );
            }
        }
    }
}

} // namespace atvresearch::ipsw
