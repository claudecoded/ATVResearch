#include "atvresearch/ipsw/ipsw_archive.hpp"
#include "atvresearch/macho/macho_parser.hpp"

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

void printUsage() {
    std::cout << R"(

ATVResearch
Apple TV firmware research and binary analysis toolkit

Usage:

  atvresearch macho info <file>
  atvresearch macho segments <file>
  atvresearch macho load-commands <file>

  atvresearch ipsw info <file>
  atvresearch ipsw list <file>
  atvresearch ipsw extract <file> <directory>

Examples:

  atvresearch macho info kernelcache
  atvresearch macho segments kernelcache
  atvresearch macho load-commands kernelcache

  atvresearch ipsw info AppleTV.ipsw
  atvresearch ipsw list AppleTV.ipsw
  atvresearch ipsw extract AppleTV.ipsw extracted/

)";
}

std::string formatHex(
    std::uint64_t value
) {
    std::ostringstream stream;

    stream
        << "0x"
        << std::hex
        << value;

    return stream.str();
}

int machoInfo(
    const std::filesystem::path& path
) {
    const auto file =
        atvresearch::macho::MachOParser::parse(path);

    std::cout
        << "File: "
        << path.string()
        << '\n';

    std::cout
        << "Format: "
        << (file.universal
                ? "Universal/FAT"
                : "Mach-O")
        << '\n';

    std::cout
        << "Images: "
        << file.images.size()
        << "\n\n";

    if (file.universal) {
        std::cout
            << "Architectures:\n";

        for (const auto& architecture :
             file.architectures) {

            std::cout
                << "  "
                << atvresearch::macho::
                       MachOParser::
                           cpuTypeName(
                               architecture.cpuType
                           )
                << "  offset="
                << architecture.offset
                << "  size="
                << architecture.size
                << '\n';
        }

        std::cout << '\n';
    }

    for (std::size_t index = 0;
         index < file.images.size();
         ++index) {

        const auto& image =
            file.images[index];

        std::cout
            << "Image #"
            << index
            << '\n';

        std::cout
            << "  Offset: "
            << image.fileOffset
            << '\n';

        std::cout
            << "  Architecture: "
            << atvresearch::macho::
                   MachOParser::
                       cpuTypeName(
                           image.header.cpuType
                       )
            << '\n';

        std::cout
            << "  File type: "
            << atvresearch::macho::
                   MachOParser::
                       fileTypeName(
                           image.header.fileType
                       )
            << '\n';

        std::cout
            << "  64-bit: "
            << (image.is64Bit
                    ? "yes"
                    : "no")
            << '\n';

        std::cout
            << "  Endianness: "
            << (image.bigEndian
                    ? "big"
                    : "little")
            << '\n';

        std::cout
            << "  Load commands: "
            << image.header.commandCount
            << '\n';

        std::cout
            << "  Load command size: "
            << image.header.commandSize
            << '\n';

        std::cout
            << "  Flags: "
            << formatHex(image.header.flags)
            << "\n\n";
    }

    return 0;
}

int machoSegments(
    const std::filesystem::path& path
) {
    const auto file =
        atvresearch::macho::MachOParser::parse(path);

    for (std::size_t index = 0;
         index < file.images.size();
         ++index) {

        const auto& image =
            file.images[index];

        std::cout
            << "Image #"
            << index
            << '\n';

        for (const auto& segment :
             image.segments) {

            std::cout
                << "  "
                << segment.name
                << '\n';

            std::cout
                << "    vmaddr:  "
                << formatHex(
                    segment.virtualAddress
                )
                << '\n';

            std::cout
                << "    vmsize:  "
                << formatHex(
                    segment.virtualSize
                )
                << '\n';

            std::cout
                << "    fileoff: "
                << formatHex(
                    segment.fileOffset
                )
                << '\n';

            std::cout
                << "    filesize:"
                << formatHex(
                    segment.fileSize
                )
                << '\n';

            std::cout
                << "    sections: "
                << segment.sectionCount
                << '\n';
        }

        std::cout << '\n';
    }

    return 0;
}

int machoLoadCommands(
    const std::filesystem::path& path
) {
    const auto file =
        atvresearch::macho::MachOParser::parse(path);

    for (std::size_t index = 0;
         index < file.images.size();
         ++index) {

        const auto& image =
            file.images[index];

        std::cout
            << "Image #"
            << index
            << '\n';

        for (const auto& command :
             image.loadCommands) {

            std::cout
                << "  "
                << command.name
                << "  size="
                << command.size
                << "  command="
                << formatHex(command.command)
                << '\n';
        }

        std::cout << '\n';
    }

    return 0;
}

int ipswInfo(
    const std::filesystem::path& path
) {
    const auto info =
        atvresearch::ipsw::IPSWArchive::inspect(
            path
        );

    std::cout
        << "File: "
        << path.string()
        << '\n';

    std::cout
        << "Entries: "
        << info.entryCount
        << '\n';

    std::cout
        << "Uncompressed size: "
        << info.totalSize
        << " bytes\n";

    return 0;
}

int ipswList(
    const std::filesystem::path& path
) {
    const auto entries =
        atvresearch::ipsw::IPSWArchive::list(
            path
        );

    for (const auto& entry : entries) {
        std::cout
            << (entry.directory
                    ? "DIR  "
                    : "FILE ")
            << std::setw(12)
            << entry.size
            << "  "
            << entry.path
            << '\n';
    }

    return 0;
}

int ipswExtract(
    const std::filesystem::path& path,
    const std::filesystem::path& output
) {
    atvresearch::ipsw::IPSWArchive::extract(
        path,
        output
    );

    std::cout
        << "Extracted to: "
        << output.string()
        << '\n';

    return 0;
}

} // namespace

int main(
    int argc,
    char* argv[]
) {
    try {
        if (argc < 2) {
            printUsage();
            return 1;
        }

        const std::string category =
            argv[1];

        if (category == "--help" ||
            category == "-h") {

            printUsage();
            return 0;
        }

        if (argc < 4) {
            printUsage();
            return 1;
        }

        const std::string command =
            argv[2];

        if (category == "macho") {
            const std::filesystem::path file =
                argv[3];

            if (command == "info") {
                return machoInfo(file);
            }

            if (command == "segments") {
                return machoSegments(file);
            }

            if (command == "load-commands") {
                return machoLoadCommands(file);
            }
        }

        if (category == "ipsw") {
            const std::filesystem::path file =
                argv[3];

            if (command == "info") {
                return ipswInfo(file);
            }

            if (command == "list") {
                return ipswList(file);
            }

            if (command == "extract") {
                if (argc < 5) {
                    std::cerr
                        << "Missing output directory.\n";

                    return 1;
                }

                return ipswExtract(
                    file,
                    argv[4]
                );
            }
        }

        std::cerr
            << "Unknown command.\n";

        printUsage();

        return 1;
    }
    catch (const std::exception& error) {
        std::cerr
            << "Error: "
            << error.what()
            << '\n';

        return 1;
    }
}
