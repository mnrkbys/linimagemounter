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
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time

VERSION = "20240712a"

CMD_XMOUNT = "/usr/bin/xmount"
CMD_KPARTX = "/usr/sbin/kpartx"
CMD_LOSETUP = "/usr/sbin/losetup"
CMD_LSBLK = "/usr/bin/lsblk"
CMD_BLKID = "/usr/sbin/blkid"
CMD_MOUNT = "/usr/bin/mount"
CMD_UMOUNT = "/usr/bin/umount"
CMD_DMSETUP = "/usr/sbin/dmsetup"
CMD_FUSERMOUNT = "/usr/bin/fusermount"

IMAGEINFO_JSON_PATH = os.path.abspath(os.path.expanduser("~/.linimagemounter/linimagemounter.json"))


class MountInfo:
    def __init__(self, device: str, dm_name: str, mountable: bool, mountpoint: str | None, filesystem: str) -> None:
        self.device = device
        self.dm_name = dm_name
        self.mountable = mountable
        self.mountpoint = mountpoint
        self.filesystem = filesystem

    @staticmethod
    def mount_info_to_dict(mount_info: MountInfo) -> dict:
        if isinstance(mount_info, MountInfo):
            return mount_info.__dict__
        raise TypeError(f"Object of type '{mount_info.__class__.__name__}' is not JSON serializable.")

    def print_mounting(self) -> None:
        if self.mountable:
            print(f"/dev/mapper/{self.device} -> /dev/{self.dm_name} is mounted on {self.mountpoint} as {self.filesystem}.")
        else:
            print(f"/dev/mapper/{self.device} -> /dev/{self.dm_name} is not mountable.")

    def print_info(self, indent=0) -> None:
        print(" " * indent + f"Device: {self.device}")
        print(" " * indent + f"Device Mapper Name: {self.dm_name}")
        print(" " * indent + f"Mountable: {self.mountable}")
        print(" " * indent + f"Mountpoint: {self.mountpoint}")
        print(" " * indent + f"Filesystem: {self.filesystem}")


class ImageInfo:
    def __init__(
        self,
        image: str,
        image_path_hash: str,
        image_mountpoint: str,
        xmount_image_path: str,
        xmount_cache_path: str,
        loopback_device: str,
    ) -> None:
        self.image = image
        self.image_path_hash = image_path_hash
        self.image_mountpoint = image_mountpoint
        self.xmount_image_path = xmount_image_path
        self.xmount_cache_path = xmount_cache_path
        self.loopback_device = loopback_device

    @staticmethod
    def image_info_to_dict(image_info: ImageInfo) -> dict:
        if isinstance(image_info, ImageInfo):
            return image_info.__dict__
        raise TypeError(f"Object of type '{image_info.__class__.__name__}' is not JSON serializable.")

    def print_info(self, indent=0) -> None:
        print(" " * indent + f"Image: {self.image}")
        print(" " * indent + f"Image Path Hash: {self.image_path_hash}")
        print(" " * indent + f"Image Mountpoint: {self.image_mountpoint}")
        print(" " * indent + f"Xmount Image Path: {self.xmount_image_path}")
        print(" " * indent + f"Xmount Cache Path: {self.xmount_cache_path}")
        print(" " * indent + f"Loopback Device: {self.loopback_device}")


class LinImageMounter:
    def __init__(self, mountpoint_base: str, image_info: list[ImageInfo], mount_info: list[MountInfo]) -> None:
        self.mountpoint_base = mountpoint_base
        self.image_info = image_info
        self.mount_info = mount_info

    def linimagemounter_to_dict(self, linimagemounter: LinImageMounter) -> dict:
        if isinstance(linimagemounter, LinImageMounter):
            return {
                "mountpoint_base": linimagemounter.mountpoint_base,
                "image_info": [ImageInfo.image_info_to_dict(ii) for ii in linimagemounter.image_info],
                "mount_info": [MountInfo.mount_info_to_dict(mi) for mi in linimagemounter.mount_info],
            }
        raise TypeError(f"Object of type '{linimagemounter.__class__.__name__}' is not JSON serializable.")

    def save_json(self, image_info_json_path: str) -> bool:
        try:
            json_data_path = os.path.abspath(os.path.expanduser(image_info_json_path))
            json_data_dir = os.path.dirname(json_data_path)
            if os.path.isfile(json_data_dir):
                print("JSON data directory is a file.")
                return False

            os.makedirs(json_data_dir, exist_ok=True)

            mount_info_json = json.dumps(self, default=self.linimagemounter_to_dict, indent=4)
            with open(json_data_path, "w") as f:
                f.write(mount_info_json)

        except OSError as e:
            print(f"Failed to save image info JSON file: {e}")
            return False

        else:
            return True

    def load_json(self, image_info_json_path: str) -> bool:
        try:
            with open(os.path.abspath(os.path.expanduser(image_info_json_path))) as f:
                image_info_dict = json.load(f)

            self.mountpoint_base = image_info_dict["mountpoint_base"]
            self.image_info = [ImageInfo(**ii_dict) for ii_dict in image_info_dict["image_info"]]
            self.mount_info = [MountInfo(**mi_dict) for mi_dict in image_info_dict["mount_info"]]

        except OSError as e:
            print(f"Failed to load image info JSON file: {e}")
            return False

        else:
            return True

    def print_info(self) -> None:
        print(f"Mountpoint Base: {self.mountpoint_base}")
        print("Image Info:")
        for info in self.image_info:
            info.print_info(indent=2)
            print()
        print("Mount Info:")
        for info in self.mount_info:
            info.print_info(indent=2)
            print()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="LinImageMounter", description="Mounts Linux disk image files for forensics on Linux.")
    parser.add_argument("command", type=str, choices=["mount", "unmount", "status"], help="Command to execute.")
    parser.add_argument(
        "-t",
        "--type",
        type=str,
        choices=["ewf", "raw"],
        default="ewf",
        help="Type of the disk image file. Required for the 'mount' command. (Default: ewf)",
    )
    parser.add_argument("-i", "--image", type=str, nargs="+", help="Path to the disk image file. Required for the 'mount' command.")
    parser.add_argument(
        "--mountpoint-base",
        type=str,
        default="/mnt/linimagemounter",
        help="Base path to the mountpoint. (Default: /mnt/linimagemounter)",
    )
    parser.add_argument("-rw", "--read-write", action="store_true", default=False, help="Mount the image in read-write mode. (Default: False)")
    parser.add_argument(
        "--reuse-cache",
        action="store_true",
        default=False,
        help="Reuse/Keep the xmount cache file when the 'mount'/'unmount' command is executed. (Default: False)",
    )
    # parser.add_argument("--force", action="store_true", default=False, help="Force the command to execute. (Default: False)")
    parser.add_argument("--debug", action="store_true", default=False, help="Enable debug mode. (Default: False)")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args()


def debug_print(*dp_msgs) -> None:
    if args.debug:
        print("[DEBUG]", *dp_msgs)


def platform_is_linux() -> bool:
    return platform.system() == "Linux"


def check_root_privilege() -> bool:
    return os.geteuid() == 0


def check_dependencies() -> bool:
    dependencies = (CMD_XMOUNT, CMD_KPARTX, CMD_LOSETUP, CMD_LSBLK, CMD_BLKID, CMD_MOUNT, CMD_UMOUNT, CMD_DMSETUP, CMD_FUSERMOUNT)
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


def run_xmount(linimagemounter: LinImageMounter) -> bool:
    debug_print("===== Run Xmount =====")
    # Check if the xmount cache dir exists
    xmount_cache_dir = os.path.abspath(os.path.expanduser("~/.xmount-cache"))
    if os.path.isfile(xmount_cache_dir):
        print("xmount cache directory is a file.")
        return False

    os.makedirs(xmount_cache_dir, exist_ok=True)

    for image_info in linimagemounter.image_info:
        xmount_cache_filename = image_info.image_path_hash + "_" + os.path.splitext(os.path.basename(image_info.image))[0] + ".cache"
        xmount_cache_path = os.path.join(xmount_cache_dir, xmount_cache_filename)
        image_info.xmount_cache_path = xmount_cache_path

        if os.path.isfile(xmount_cache_path):
            if not args.reuse_cache:
                os.remove(xmount_cache_path)
                debug_print(f"Removed xmount cache: {xmount_cache_path}")
            elif args.reuse_cache:
                debug_print(f"Reuse xmount cache: {xmount_cache_path}")
        else:
            debug_print(f"xmount cache not found: {xmount_cache_path}")

        # Check if the image exists
        if not os.path.isfile(image_info.image):
            print("Disk image file not found.")
            return False

        # Check if the mountpoint exists and is not mounted
        if os.path.isfile(image_info.image_mountpoint):
            print("Mountpoint of the image file is a file.")
            return False

        os.makedirs(image_info.image_mountpoint, exist_ok=True)

        if os.path.ismount(image_info.image_mountpoint):
            print("Mountpoint of the image file is already mounted.")
            return False

        # Mount the image
        result = run_cmd(
            [CMD_XMOUNT, "--in", args.type, image_info.image, "--out", "vmdk", "--cache", xmount_cache_path, image_info.image_mountpoint],
        )
        if result.returncode != 0 or not os.path.ismount(image_info.image_mountpoint):
            print("Failed to run xmount.")
            return False

    return True


def run_kpartx(linimagemounter: LinImageMounter) -> bool:
    debug_print("===== Run Kpartx =====")
    for image_info in linimagemounter.image_info:
        raw_image_filename = os.path.splitext(os.path.basename(image_info.image))[0] + ".dd"
        xmount_image_path = os.path.join(image_info.image_mountpoint, raw_image_filename)
        image_info.xmount_image_path = xmount_image_path

        result = run_cmd([CMD_KPARTX, "-av", xmount_image_path])
        if result.returncode != 0:
            print("Failed to run kpartx.")
            return False

    return True


def run_loseup(linimagemounter: LinImageMounter, sleeptime=2) -> bool:
    debug_print("===== Run Losetup =====")
    # Wait for the device mapper devices to be created
    time.sleep(sleeptime)
    result = run_cmd([CMD_LOSETUP, "--json"])
    if result.returncode != 0:
        print("Failed to run losetup.")
        return False

    data = json.loads(result.stdout)
    for loopback_device in data["loopdevices"]:
        for image_info in linimagemounter.image_info:
            if loopback_device["back-file"] == image_info.xmount_image_path:
                image_info.loopback_device = os.path.basename(loopback_device["name"])
                break

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
        devices = [info.device for info in mount_info]
        if device["name"] not in devices:
            dm_name = dev_map[device["name"]]
            mount_info.append(MountInfo(device=device["name"], dm_name=dm_name, mountable=True, mountpoint=None, filesystem=""))


def run_lsblk(linimagemounter: LinImageMounter) -> bool:
    debug_print("===== Run Lsblk =====")
    dev_map = _get_dev_map()

    result = run_cmd([CMD_LSBLK, "--json"])
    if result.returncode != 0:
        print("Failed to run lsblk.")
        return False

    data = json.loads(result.stdout)
    for device in data["blockdevices"]:
        for image_info in linimagemounter.image_info:
            if device["name"] == image_info.loopback_device:
                _lsblk_recursive(device, linimagemounter.mount_info, dev_map)
                break

    return True


def run_blkid(linimagemounter: LinImageMounter) -> bool:
    debug_print("===== Run Blkid =====")
    result = run_cmd([CMD_BLKID])
    if result.returncode != 0:
        print("Failed to run blkid.")
        return False

    for mount_info in linimagemounter.mount_info:
        for line in result.stdout.splitlines():
            device = line.split(": ")[0]
            device_info = line.split(": ")[1]
            try:
                if device.endswith(mount_info.device):
                    mount_info.filesystem = {k: v.strip('"') for k, v in [field.split("=") for field in device_info.split()]}["TYPE"]
                    if mount_info.filesystem.startswith("fat"):
                        mount_info.filesystem = "vfat"
                    elif mount_info.filesystem in ("swap",):
                        mount_info.mountable = False
                    debug_print(f"Device: {device}, Filesystem: {mount_info.filesystem}, Mountable: {mount_info.mountable}")
                    break
            except KeyError:
                debug_print(f"'{line}' has no TYPE field.")
                continue

    return True


def run_mount(linimagemounter: LinImageMounter) -> bool:
    debug_print("===== Run Mount =====")
    for mount_info in linimagemounter.mount_info:
        if mount_info.mountable and mount_info.mountpoint is None:
            dm_path = os.path.join("/dev", mount_info.dm_name)
            device_mountpoint = os.path.join(linimagemounter.mountpoint_base, mount_info.device)

            if os.path.isfile(device_mountpoint):
                print(f"Mountpoint {device_mountpoint} is a file.")
                return False

            os.makedirs(device_mountpoint, exist_ok=True)

            mount_option = "rw" if args.read_write else "ro"
            result = run_cmd([CMD_MOUNT, "-t", mount_info.filesystem, "-o", mount_option, dm_path, device_mountpoint])
            if result.returncode != 0 or not os.path.ismount(device_mountpoint):
                print(f"Failed to mount {dm_path} to {device_mountpoint}.")
                return False

            mount_info.mountpoint = device_mountpoint

    return True


def mount_image(images: list[str], mountpoint_base: str) -> tuple[bool, LinImageMounter | None]:
    if os.path.isfile(IMAGEINFO_JSON_PATH):
        print("Image is already mounted.")
        return False, None

    image_info = []
    for image in images:
        image_path_hash = hashlib.sha1(image.encode()).hexdigest()
        image_mountpoint = os.path.join(mountpoint_base, os.path.join("_images", image_path_hash))
        image_info.append(
            ImageInfo(
                image=image,
                image_path_hash=image_path_hash,
                image_mountpoint=image_mountpoint,
                xmount_image_path="",
                xmount_cache_path="",
                loopback_device="",
            ),
        )

    linimagemounter = LinImageMounter(mountpoint_base=mountpoint_base, image_info=image_info, mount_info=[])

    result = run_xmount(linimagemounter)
    if not result:
        return False, linimagemounter

    result = run_kpartx(linimagemounter)
    if not result:
        return False, linimagemounter

    result = run_loseup(linimagemounter)
    if not result:
        return False, linimagemounter

    result = run_lsblk(linimagemounter)
    if not result:
        return False, linimagemounter

    result = run_blkid(linimagemounter)
    if not result:
        return False, linimagemounter

    result = run_mount(linimagemounter)
    if not result:
        return False, linimagemounter

    result = linimagemounter.save_json(IMAGEINFO_JSON_PATH)
    if not result:
        return False, linimagemounter

    print("Mounting info:")
    for mount_info in linimagemounter.mount_info:
        mount_info.print_mounting()
    print("Mounting succeeded.")

    return True, linimagemounter


def run_umount(linimagemounter: LinImageMounter) -> bool:
    debug_print("===== Run Umount =====")
    for info in linimagemounter.mount_info:
        if info.mountpoint:
            result = run_cmd([CMD_UMOUNT, info.mountpoint])
            if result.returncode != 0:
                print(f"Failed to unmount {info.mountpoint}.")
                return False

    return True


def run_dmsetup_remove(linimagemounter: LinImageMounter) -> bool:
    debug_print("===== Run Dmsetup Remove =====")
    reverse_mount_info = sorted(linimagemounter.mount_info, key=lambda x: x.dm_name, reverse=True)
    for info in reverse_mount_info:
        device_map_path = os.path.join("/dev", info.dm_name)
        result = run_cmd([CMD_DMSETUP, "remove", device_map_path])
        if result.returncode != 0:
            print(f"Failed to remove device map {device_map_path}.")
            return False

    return True


def run_losetup_detach(linimagemounter: LinImageMounter) -> bool:
    debug_print("===== Run Losetup Detach =====")
    for image_info in linimagemounter.image_info:
        loopback_device_path = os.path.join("/dev", image_info.loopback_device)
        result = run_cmd([CMD_LOSETUP, "-d", loopback_device_path])
        if result.returncode != 0:
            print(f"Failed to detach loopback device {loopback_device_path}.")
            return False

    return True


def run_fusermount_unmount(linimagemounter: LinImageMounter) -> bool:
    debug_print("===== Run Fusermount Unmount =====")
    for image_info in linimagemounter.image_info:
        result = run_cmd([CMD_FUSERMOUNT, "-u", image_info.image_mountpoint])
        if result.returncode != 0:
            print(f"Failed to unmount {image_info.image_mountpoint}.")
            return False

    try:
        shutil.rmtree(linimagemounter.mountpoint_base)
    except OSError as e:
        print(f"Failed to remove mountpoint base {linimagemounter.mountpoint_base}: {e}")
        return False
    else:
        return True


def remove_xmount_cache(linimagemounter: LinImageMounter) -> bool:
    debug_print("===== Remove Xmount Cache =====")
    try:
        for image_info in linimagemounter.image_info:
            if os.path.isfile(image_info.xmount_cache_path):
                if not args.reuse_cache:
                    os.remove(image_info.xmount_cache_path)
                    debug_print(f"Removed xmount cache: {image_info.xmount_cache_path}")
                else:
                    debug_print(f"Keep xmount cache: {image_info.xmount_cache_path}")
            else:
                debug_print(f"xmount cache not found: {image_info.xmount_cache_path}")

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


def unmount_image() -> tuple[bool, LinImageMounter | None]:
    linimagemounter = LinImageMounter(mountpoint_base="", image_info=[], mount_info=[])
    result = linimagemounter.load_json(IMAGEINFO_JSON_PATH)
    if not result:
        return False, None

    print("Mounting info:")
    for mount_info in linimagemounter.mount_info:
        mount_info.print_mounting()

    result = run_umount(linimagemounter)
    if not result:
        return False, linimagemounter

    result = run_dmsetup_remove(linimagemounter)
    if not result:
        return False, linimagemounter

    result = run_losetup_detach(linimagemounter)
    if not result:
        return False, linimagemounter

    result = run_fusermount_unmount(linimagemounter)
    if not result:
        return False, linimagemounter

    result = remove_xmount_cache(linimagemounter)
    if not result:
        return False, linimagemounter

    result = remove_image_info_json(IMAGEINFO_JSON_PATH)
    if not result:
        return False, linimagemounter

    print("Unmounting succeeded.")

    return True, linimagemounter


def check_status() -> bool:
    if not os.path.exists(IMAGEINFO_JSON_PATH):
        print("No image is mounted.")
        return True

    linimagemounter = LinImageMounter(mountpoint_base="", image_info=[], mount_info=[])
    result = linimagemounter.load_json(IMAGEINFO_JSON_PATH)
    if not result:
        return False

    print("Current status:")
    linimagemounter.print_info()

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
    linimagemounter = None
    if args.command == "mount":
        if not args.image:
            print("Disk image file is required.")
            sys.exit(1)

        # Get absolute paths
        seen_images = set()
        for image in args.image:
            full_path = os.path.abspath(os.path.expanduser(image))
            if full_path not in seen_images:
                seen_images.add(full_path)
        args.mountpoint_base = os.path.abspath(os.path.expanduser(args.mountpoint_base))
        result, linimagemounter = mount_image(list(seen_images), args.mountpoint_base)
    elif args.command == "unmount":
        result, linimagemounter = unmount_image()
    elif args.command == "status":
        result = check_status()
    else:
        print("Invalid command.")
        sys.exit(1)

    if not result:
        print("Failed to execute the command.")
        if args.debug and linimagemounter is not None:
            linimagemounter.print_info()
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    args = parse_arguments()
    main()
