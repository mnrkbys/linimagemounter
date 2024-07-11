#!/usr/bin/env python3
#
# linimagemounter.py
# Linux Image Mounter can mount Linux disk image files on Linux for forensics.
#
# Copyright 2024 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time

VERSION = "20240711"

CMD_XMOUNT = "/usr/bin/xmount"
CMD_KPARTX = "/usr/sbin/kpartx"
CMD_LSBLK = "/usr/bin/lsblk"
CMD_BLKID = "/usr/sbin/blkid"
CMD_MOUNT = "/usr/bin/mount"
CMD_UMOUNT = "/usr/bin/umount"
CMD_DMSETUP = "/usr/sbin/dmsetup"
CMD_LOSETUP = "/usr/sbin/losetup"
CMD_FUSERMOUNT = "/usr/bin/fusermount"

IMAGEINFO_JSON_PATH = os.path.abspath(os.path.expanduser("~/.linimagemounter/image_info.json"))


class MountInfo:
    def __init__(self, device: str, dm_name: str, mountable: bool, mountpoint: str | None, filesystem: str) -> None:
        self.device = device
        self.dm_name = dm_name
        self.mountable = mountable
        self.mountpoint = mountpoint
        self.filesystem = filesystem

    def print_info(self) -> None:
        if self.mountable:
            print(f"/dev/mapper/{self.device} -> /dev/{self.dm_name} is mounted on {self.mountpoint} as {self.filesystem}.")
        else:
            print(f"/dev/mapper/{self.device} -> /dev/{self.dm_name} is not mountable.")


class ImageInfo:
    def __init__(self, image: str, mountpoint_base: str, image_mountpoint: str, loopback_device: str, mount_info: list[MountInfo]) -> None:
        self.image = image
        self.mountpoint_base = mountpoint_base
        self.image_mountpoint = image_mountpoint
        self.loopback_device = loopback_device
        self.mount_info = mount_info

    def _mount_info_to_dict(self, mount_info: MountInfo) -> dict:
        if isinstance(mount_info, MountInfo):
            return mount_info.__dict__
        raise TypeError(f"Object of type '{mount_info.__class__.__name__}' is not JSON serializable.")

    def _image_info_to_dict(self, image_info: ImageInfo) -> dict:
        if isinstance(image_info, ImageInfo):
            return {
                "image": image_info.image,
                "mountpoint_base": image_info.mountpoint_base,
                "image_mountpoint": image_info.image_mountpoint,
                "loopback_device": image_info.loopback_device,
                "mount_info": [self._mount_info_to_dict(mi) for mi in image_info.mount_info],
            }
        raise TypeError(f"Object of type '{obj.__class__.__name__}' is not JSON serializable.")

    def save_image_info(self, image_info_json_path: str) -> bool:
        try:
            json_data_path = os.path.abspath(os.path.expanduser(image_info_json_path))
            json_data_dir = os.path.dirname(json_data_path)
            if os.path.isfile(json_data_dir):
                print("JSON data directory is a file.")
                return False

            if not os.path.exists(json_data_dir):
                os.makedirs(json_data_dir, exist_ok=True)

            mount_info_json = json.dumps(self, default=self._image_info_to_dict, indent=4)
            with open(json_data_path, "w") as f:
                f.write(mount_info_json)

        except OSError as e:
            print(f"Failed to save image info JSON file: {e}")
            return False

        else:
            return True

    def load_image_info(self, image_info_json_path: str) -> bool:
        try:
            with open(os.path.abspath(os.path.expanduser(image_info_json_path))) as f:
                image_info_dict = json.load(f)

            self.image = image_info_dict["image"]
            self.mountpoint_base = image_info_dict["mountpoint_base"]
            self.image_mountpoint = image_info_dict["image_mountpoint"]
            self.loopback_device = image_info_dict["loopback_device"]
            self.mount_info = [MountInfo(**mi_dict) for mi_dict in image_info_dict["mount_info"]]

        except OSError as e:
            print(f"Failed to load image info JSON file: {e}")
            return False

        else:
            return True

    def print_info(self) -> None:
        print(f"Image: {self.image}")
        print(f"Mountpoint Base: {self.mountpoint_base}")
        print(f"Image Mountpoint: {self.image_mountpoint}")
        print(f"Loopback Device: {self.loopback_device}")
        print("Mount Info:")
        for info in self.mount_info:
            print(f"  Device: {info.device}")
            print(f"  Device Mapper Name: {info.dm_name}")
            print(f"  Mountable: {info.mountable}")
            print(f"  Mountpoint: {info.mountpoint}")
            print(f"  Filesystem: {info.filesystem}")
            print()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="LinImageMounter", description="Mounts Linux disk image files for forensics on Linux.")
    parser.add_argument("command", type=str, choices=["mount", "unmount", "status"], help="Command to execute.")
    parser.add_argument("-i", "--image", type=str, default="", help="Path to the disk image file. Required for the 'mount' command. (Default: '')")
    parser.add_argument(
        "--mountpoint_base",
        type=str,
        default="/mnt/linimagemounter",
        help="Base path to the mountpoint. (Default: /mnt/linimagemounter)",
    )
    parser.add_argument("-rw", "--read-write", action="store_true", default=False, help="Mount the image in read-write mode. (Default: False)")
    parser.add_argument(
        "--retain-cache",
        action="store_true",
        default=False,
        help="Retain the xmount cache file when the 'unmount' command is executed. (Default: False)",
    )
    # parser.add_argument("--force", action="store_true", default=False, help="Force the command to execute. (Default: False)")
    parser.add_argument("--debug", action="store_true", default=False, help="Enable debug mode. (Default: False)")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args()


def debug_print(*dp_msgs) -> None:
    if args.debug:
        print(*dp_msgs)


def platform_is_linux() -> bool:
    return platform.system() == "Linux"


def check_root_privilege() -> bool:
    return os.geteuid() == 0


def check_dependencies() -> bool:
    dependencies = (CMD_XMOUNT, CMD_KPARTX, CMD_LSBLK, CMD_BLKID, CMD_MOUNT, CMD_UMOUNT, CMD_DMSETUP, CMD_LOSETUP, CMD_FUSERMOUNT)
    check_results: list[bool] = []
    for dependency in dependencies:
        exist = os.path.isfile(dependency)
        if not exist:
            print(f"Dependency not found: {dependency}")
        check_results.append(exist)

    return all(check_results)


def run_cmd(cmd_line: list[str]) -> subprocess.CompletedProcess:
    debug_print(" ".join(cmd_line))
    result = subprocess.run(cmd_line, capture_output=True, text=True, encoding="utf-8", check=False)
    debug_print(f"return code: {result.returncode}")
    debug_print(f"stdout: {result.stdout}")
    debug_print(f"stderr: {result.stderr}")
    return result


def run_xmount(image_info: ImageInfo) -> bool:
    debug_print("===== Run Xmount =====")
    # Check if the image exists
    if not os.path.isfile(image_info.image):
        print("Disk image file not found.")
        return False

    # Check if the xmount cache file exists
    xmount_cache_dir = os.path.abspath(os.path.expanduser("~/.xmount-cache"))
    if os.path.isfile(xmount_cache_dir):
        print("xmount cache directory is a file.")
        return False

    if not os.path.exists(xmount_cache_dir):
        os.makedirs(xmount_cache_dir, exist_ok=True)

    xmount_cache_filename = os.path.splitext(os.path.basename(image_info.image))[0] + ".cache"
    xmount_cache_path = os.path.join(xmount_cache_dir, xmount_cache_filename)
    if not args.retain_cache and os.path.isfile(xmount_cache_path):
        os.remove(xmount_cache_path)

    # Check if the mountpoint exists and is not mounted
    if os.path.isfile(image_info.image_mountpoint):
        print("Mountpoint of the image file is a file.")
        return False

    if not os.path.exists(image_info.image_mountpoint):
        os.makedirs(image_info.image_mountpoint, exist_ok=True)

    if os.path.ismount(image_info.image_mountpoint):
        print("Mountpoint of the image file is already mounted.")
        return False

    # Mount the image
    result = run_cmd([CMD_XMOUNT, "--in", "ewf", image_info.image, "--out", "vmdk", "--cache", xmount_cache_path, image_info.image_mountpoint])
    if result.returncode != 0 or not os.path.ismount(image_info.image_mountpoint):
        print("Failed to run xmount.")
        return False

    return True


def run_kpartx(image_info: ImageInfo, sleeptime=3) -> bool:
    debug_print("===== Run Kpartx =====")
    raw_image_filename = os.path.splitext(os.path.basename(image_info.image))[0] + ".dd"
    mounted_image_path = os.path.join(image_info.image_mountpoint, raw_image_filename)
    mount_info: list[MountInfo] = []

    result = run_cmd([CMD_KPARTX, "-av", mounted_image_path])
    if result.returncode != 0:
        print("Failed to run kpartx.")
        return False

    loopback_device = ""
    for line in result.stdout.splitlines():
        if match := re.search(r"(loop\d+)p\d+", line):
            loopback_device = match.group(1)
            break

    if not loopback_device:
        print("Failed to find loopback device.")
        return False

    image_info.loopback_device = loopback_device
    image_info.mount_info = mount_info
    return True


def _get_dev_map() -> dict[str, str]:
    dev_map: dict[str, str] = {}
    for file in os.listdir("/dev/mapper"):
        mapped_device_path = os.path.join("/dev/mapper", file)
        if file not in ("control",) and os.path.islink(mapped_device_path):
            dm_name = os.path.basename(os.readlink(mapped_device_path))
            if file not in dev_map and dm_name.startswith("dm-"):
                dev_map[file] = dm_name

    return dev_map


def _lsblk_recursive(device: dict, mount_info: list[MountInfo], dev_map: dict[str, str]) -> None:
    if device.get("children"):
        if device["name"] in dev_map:
            dm_name = dev_map[device["name"]]
            mount_info.append(MountInfo(device=device["name"], dm_name=dm_name, mountable=False, mountpoint=None, filesystem=""))

        for child in device["children"]:
            _lsblk_recursive(child, mount_info, dev_map)

    elif device["name"] in dev_map:
        dm_name = dev_map[device["name"]]
        mount_info.append(MountInfo(device=device["name"], dm_name=dm_name, mountable=True, mountpoint=None, filesystem=""))


def run_lsblk(image_info: ImageInfo, sleeptime=2) -> bool:
    debug_print("===== Run Lsblk =====")
    # Wait for the device mapper devices to be created
    time.sleep(sleeptime)
    dev_map = _get_dev_map()

    result = run_cmd([CMD_LSBLK, "--json"])
    if result.returncode != 0:
        print("Failed to run lsblk.")
        return False

    data = json.loads(result.stdout)
    for device in data["blockdevices"]:
        if device["name"] == image_info.loopback_device:
            _lsblk_recursive(device, image_info.mount_info, dev_map)

    return True


def run_blkid(image_info: ImageInfo) -> bool:
    debug_print("===== Run Blkid =====")
    result = run_cmd([CMD_BLKID])
    if result.returncode != 0:
        print("Failed to run blkid.")
        return False

    for info in image_info.mount_info:
        for line in result.stdout.splitlines():
            device = line.split(": ")[0]
            device_info = line.split(": ")[1]
            try:
                if device.endswith(info.device):
                    info.filesystem = {k: v.strip('"') for k, v in [field.split("=") for field in device_info.split()]}["TYPE"]
                    if info.filesystem.startswith("fat"):
                        info.filesystem = "vfat"
                    break
            except KeyError:
                debug_print(f"'{line}' has no TYPE field.")
                continue

    return True


def run_mount(image_info: ImageInfo) -> bool:
    debug_print("===== Run Mount =====")
    for info in image_info.mount_info:
        if info.mountable and info.mountpoint is None:  # If info.mountpoint is None, it means the partition/lvm is not mounted yet.
            dm_path = os.path.join("/dev", info.dm_name)
            image_basename = os.path.splitext(os.path.basename(image_info.image))[0]
            device_mountpoint = os.path.join(image_info.mountpoint_base, os.path.join(image_basename, info.device))

            if os.path.isfile(device_mountpoint):
                print(f"Mountpoint {device_mountpoint} is a file.")
                return False

            if not os.path.exists(device_mountpoint):
                os.makedirs(device_mountpoint, exist_ok=True)

            mount_option = "rw" if args.read_write else "ro"
            result = run_cmd([CMD_MOUNT, "-t", info.filesystem, "-o", mount_option, dm_path, device_mountpoint])
            if result.returncode != 0 or not os.path.ismount(device_mountpoint):
                print(f"Failed to mount {dm_path} to {device_mountpoint}.")
                return False

            info.mountpoint = device_mountpoint

    return True


def mount_image(image: str, mountpoint_base: str) -> bool:
    if os.path.isfile(IMAGEINFO_JSON_PATH):
        print("Image is already mounted.")
        return False

    image_basename = os.path.splitext(os.path.basename(image))[0]
    image_mountpoint = os.path.join(mountpoint_base, os.path.join(image_basename, "_image"))
    image_info = ImageInfo(image=image, mountpoint_base=mountpoint_base, image_mountpoint=image_mountpoint, loopback_device="", mount_info=[])

    result = run_xmount(image_info)
    if not result:
        return False

    result = run_kpartx(image_info)
    if not result:
        return False

    result = run_lsblk(image_info)
    if not result:
        return False

    result = run_blkid(image_info)
    if not result:
        return False

    result = run_mount(image_info)
    if not result:
        return False

    result = image_info.save_image_info(IMAGEINFO_JSON_PATH)
    if not result:
        return False

    print("Mounting info:")
    for mount_info in image_info.mount_info:
        mount_info.print_info()
    print("Mounting succeeded.")

    return True


def run_umount(image_info: ImageInfo) -> bool:
    debug_print("===== Run Umount =====")
    for info in image_info.mount_info:
        if info.mountpoint:
            result = run_cmd([CMD_UMOUNT, info.mountpoint])
            if result.returncode != 0:
                print(f"Failed to unmount {info.mountpoint}.")
                return False

    return True


def run_dmsetup_remove(image_info: ImageInfo) -> bool:
    debug_print("===== Run Dmsetup Remove =====")
    reverse_mount_info = sorted(image_info.mount_info, key=lambda x: x.dm_name, reverse=True)
    for info in reverse_mount_info:
        device_map_path = os.path.join("/dev", info.dm_name)
        result = run_cmd([CMD_DMSETUP, "remove", device_map_path])
        if result.returncode != 0:
            print(f"Failed to remove device map {device_map_path}.")
            return False

    return True


def run_losetup_detach(image_info: ImageInfo) -> bool:
    debug_print("===== Run Losetup Detach =====")
    loopback_device_path = os.path.join("/dev", image_info.loopback_device)
    result = run_cmd([CMD_LOSETUP, "-d", loopback_device_path])
    if result.returncode != 0:
        print(f"Failed to detach loopback device {loopback_device_path}.")
        return False

    return True


def run_fusermount_unmount(image_info: ImageInfo) -> bool:
    debug_print("===== Run Fusermount Unmount =====")
    result = run_cmd([CMD_FUSERMOUNT, "-u", image_info.image_mountpoint])
    if result.returncode != 0:
        print(f"Failed to unmount {image_info.image_mountpoint}.")
        return False

    try:
        shutil.rmtree(image_info.mountpoint_base)
    except OSError as e:
        print(f"Failed to remove mountpoint base {image_info.mountpoint_base}: {e}")
        return False
    else:
        return True


def remove_xmount_cache() -> bool:
    debug_print("===== Remove Xmount Cache =====")
    try:
        if not args.retain_cache:
            xmount_cache_dir = os.path.abspath(os.path.expanduser("~/.xmount-cache"))
            shutil.rmtree(xmount_cache_dir)
            debug_print(f"Removed xmount cache directory: {xmount_cache_dir}")
        else:
            debug_print("Retained xmount cache directory.")
    except OSError as e:
        print(f"Failed to remove xmount cache directory: {e}")
        return False
    else:
        return True


def remove_image_info_json(image_info_json_path: str) -> bool:
    debug_print("===== Remove Image Info JSON =====")
    try:
        os.remove(os.path.abspath(os.path.expanduser(image_info_json_path)))
        debug_print(f"Removed image info JSON file: {image_info_json_path}")
    except OSError as e:
        print(f"Failed to remove image info JSON file: {e}")
        return False
    else:
        return True


def unmount_image() -> bool:
    image_info = ImageInfo(image="", mountpoint_base="", image_mountpoint="", loopback_device="", mount_info=[])
    result = image_info.load_image_info(IMAGEINFO_JSON_PATH)
    if not result:
        return False

    print("Mounting info:")
    for mount_info in image_info.mount_info:
        mount_info.print_info()

    result = run_umount(image_info)
    if not result:
        return False

    result = run_dmsetup_remove(image_info)
    if not result:
        return False

    result = run_losetup_detach(image_info)
    if not result:
        return False

    result = run_fusermount_unmount(image_info)
    if not result:
        return False

    result = remove_xmount_cache()
    if not result:
        return False

    result = remove_image_info_json(IMAGEINFO_JSON_PATH)
    if not result:
        return False

    print("Unmounting succeeded.")

    return True


def check_status() -> bool:
    if not os.path.exists(IMAGEINFO_JSON_PATH):
        print("No image is mounted.")
        return True

    image_info = ImageInfo(image="", mountpoint_base="", image_mountpoint="", loopback_device="", mount_info=[])
    result = image_info.load_image_info(IMAGEINFO_JSON_PATH)
    if not result:
        return False

    print("Current status:")
    image_info.print_info()

    return True


def main() -> None:
    if not platform_is_linux():
        print("This script only supports Linux.")
        sys.exit(1)

    if not check_root_privilege():
        print("This script requires root privilege.")
        sys.exit(1)

    if not check_dependencies():
        print("Please install the required dependencies.")
        sys.exit(1)

    result = False
    if args.command == "mount":
        if not args.image:
            print("Disk image file is required.")
            sys.exit(1)

        # Get absolute paths
        args.image = os.path.abspath(os.path.expanduser(args.image))
        args.mountpoint_base = os.path.abspath(os.path.expanduser(args.mountpoint_base))

        result = mount_image(args.image, args.mountpoint_base)
    elif args.command == "unmount":
        result = unmount_image()
    elif args.command == "status":
        result = check_status()
    else:
        print("Invalid command.")
        sys.exit(1)

    if not result:
        print("Failed to execute the command.")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    args = parse_arguments()
    main()
