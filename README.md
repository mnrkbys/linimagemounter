# LinImageMounter

LinImageMounter is a Python tool designed to simplify the process of mounting disk images on Linux systems. It provides a user-friendly command line interface to mount disk images, making it easier for forensic analysts, system administrators, and enthusiasts to access the contents of disk images without the need for complex commands or manual setup.

## Features

- **Easy to Use**: Simple command line interface to mount and unmount disk images.
- **Automatic Detection**: The partition, LVM, and filesystems in the disk image are automatically detected and mounted accordingly.
- **Forensic Mode**: For forensics, disk images are mounted in read-only mode by default.
- **Unaltered Disk Images**: Disk images remain completely unaltered during mounting, even when mounted in read-write mode, ensuring the integrity of the original data.

## Requirements

- Python 3.6 or later

## Installation

To install LinImageMounter using the following command:

```bash
git clone https://github.com/mnrkbys/linimagemounter.git
```

## Usage

To mount a disk image, simply run:

```bash
sudo python3 ./linimagemounter.py mount /path/to/your/image.E01
```

*Note 1: `/mnt/linimagemounter` is the default mount point. You can specify a different mount point if needed.*

*Note 2: Mount-related information is saved in `~/.linimagemounter/image_info.json` (In many cases, saved in `/root/.linimagemounter/image_info.json`).*

Check the current mounting status:

```bash
sudo python3 ./linimagemounter.py status
```

To unmount the disk image, use:

```bash
sudo python3 ./linimagemounter.py unmount
```

For more detailed usage instructions and options, refer to the help:

```bash
linimagemounter --help
```

## Contributing

Contributions are encouraged! If you wish to contribute, please fork the repository and create a feature branch. Pull requests are greatly appreciated.

## Limitations

- LinImageMounter is based on `xmount`, and thus only raw DD and EWF (E01) disk images are supported.
- Since LinImageMounter is designed to only mount Linux disk images, errors may occur when mounting disk images from other operating systems.
- Currently, LinImageMounter supports mounting only one disk image at a time. Attempting to mount multiple images simultaneously will result in an error.
- LinImageMounter depends on some Linux-specific commands and external tools for mounting disk images. Ensure that all necessary dependencies are installed on your system.
- Currently, LinImageMounter does NOT support LUKS, eCryptfs, software RAID (mdadm), and so on.

## Testing

Please note that testing has been conducted exclusively on the [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation/) environment. Compatibility with other environments has not been verified.

## Author

[Minoru Kobayashi](https://x.com/unkn0wnbit)

## License

LinImageMounter is released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0). See the LICENSE file for more details.
