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
import uuid

VERSION = "20240716"


class MountInfo:
    def __init__(self, device: str, dm_name: str, mountable: bool, mountpoint: str | None, filesystem: str) -> None:
        self.device = device
        self.dm_name = dm_name
        self.mountable = mountable
        self.mountpoint = mountpoint
        self.filesystem = filesystem

    def convert_to_dict(self) -> dict:
        return self.__dict__

    def print_mounting(self, indent: int = 0) -> None:
        if self.mountable:
            print(" " * indent + f"/dev/mapper/{self.device} -> /dev/{self.dm_name} is mounted on {self.mountpoint} as {self.filesystem}.")
        else:
            print(" " * indent + f"/dev/mapper/{self.device} -> /dev/{self.dm_name} is not mountable.")

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

    def convert_to_dict(self) -> dict:
        return self.__dict__

    def print_info(self, indent=0) -> None:
        print(" " * indent + f"Image: {self.image}")
        print(" " * indent + f"Image Path Hash: {self.image_path_hash}")
        print(" " * indent + f"Image Mountpoint: {self.image_mountpoint}")
        print(" " * indent + f"Xmount Image Path: {self.xmount_image_path}")
        print(" " * indent + f"Xmount Cache Path: {self.xmount_cache_path}")
        print(" " * indent + f"Loopback Device: {self.loopback_device}")


class LinImageMounterSession:
    def __init__(self, mountpoint_base: str, image_info: list[ImageInfo], mount_info: list[MountInfo], session_id: str = "") -> None:
        if session_id:
            self.session_id = session_id
        else:
            self.session_id = uuid.uuid1()
        self.mountpoint_base = mountpoint_base
        self.image_info = image_info
        self.mount_info = mount_info

    def convert_to_dict(self) -> dict:
        return {
            "session_id": str(self.session_id),
            "mountpoint_base": self.mountpoint_base,
            "image_info": [ImageInfo.convert_to_dict(ii) for ii in self.image_info],
            "mount_info": [MountInfo.convert_to_dict(mi) for mi in self.mount_info],
        }

    def print_info(self) -> None:
        print(f"Session ID: {self.session_id}")
        print(f"Mountpoint Base: {self.mountpoint_base}")
        print("Image Info:")
        for info in self.image_info:
            info.print_info(indent=2)
            print()
        print("Mount Info:")
        for info in self.mount_info:
            info.print_info(indent=2)
            print()

    def print_mounting(self) -> None:
        print(f"Session ID: {self.session_id}")
        print(f"Mountpoint Base: {self.mountpoint_base}")
        for mount_info in self.mount_info:
            mount_info.print_mounting(indent=2)


class LinImageMounterManager:
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

    def __init__(self, sessions: list[LinImageMounterSession] | None = None) -> None:
        if sessions is None:
            self.sessions = []

    def check_dependencies(self) -> bool:
        dependencies = (
            self.CMD_XMOUNT,
            self.CMD_KPARTX,
            self.CMD_LOSETUP,
            self.CMD_LSBLK,
            self.CMD_BLKID,
            self.CMD_MOUNT,
            self.CMD_UMOUNT,
            self.CMD_DMSETUP,
            self.CMD_FUSERMOUNT,
        )
        check_results: list[bool] = []
        for dependency in dependencies:
            exist = os.path.isfile(dependency)
            if not exist:
                print(f"Dependency not found: {dependency}")
            check_results.append(exist)

        return all(check_results)

    def save_json(self, json_path: str) -> bool:
        try:
            json_data_path = os.path.abspath(os.path.expanduser(json_path))
            json_data_dir = os.path.dirname(json_data_path)
            if os.path.isfile(json_data_dir):
                print("JSON data directory is a file.")
                return False

            os.makedirs(json_data_dir, exist_ok=True)

            sessions_json = [session.convert_to_dict() for session in self.sessions]
            mount_info_json = json.dumps(sessions_json, indent=4)
            with open(json_data_path, "w") as f:
                f.write(mount_info_json)

        except OSError as e:
            print(f"Failed to save image info JSON file: {e}")
            return False

        else:
            return True

    def load_json(self, json_path: str, ignore_failure: bool = False) -> bool:
        try:
            with open(os.path.abspath(os.path.expanduser(json_path))) as f:
                sessions_json = json.load(f)

            self.sessions: list[LinImageMounterSession] = []
            for session in sessions_json:
                image_info = [ImageInfo(**ii_dict) for ii_dict in session["image_info"]]
                mount_info = [MountInfo(**mi_dict) for mi_dict in session["mount_info"]]
                self.sessions.append(
                    LinImageMounterSession(
                        mountpoint_base=session["mountpoint_base"],
                        image_info=image_info,
                        mount_info=mount_info,
                        session_id=session["session_id"],
                    ),
                )

        except OSError as e:
            if not ignore_failure:
                print(f"Failed to load image info JSON file: {e}")
            return False

        else:
            return True

    def mount_image(self, images: list[str], mountpoint_base: str) -> tuple[bool, LinImageMounterSession | None]:
        image_info: list[ImageInfo] = []
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

        lim_session = LinImageMounterSession(mountpoint_base=mountpoint_base, image_info=image_info, mount_info=[])

        result = self._run_xmount(lim_session)
        if not result:
            return False, lim_session

        result = self._run_kpartx(lim_session)
        if not result:
            return False, lim_session

        result = self._run_loseup(lim_session)
        if not result:
            return False, lim_session

        result = self._run_lsblk(lim_session)
        if not result:
            return False, lim_session

        result = self._run_blkid(lim_session)
        if not result:
            return False, lim_session

        result = self._run_mount(lim_session)
        if not result:
            return False, lim_session

        self.load_json(self.IMAGEINFO_JSON_PATH, ignore_failure=True)
        self.sessions.append(lim_session)

        result = self.save_json(self.IMAGEINFO_JSON_PATH)
        if not result:
            return False, lim_session

        print("Mounting info:")
        for mount_info in lim_session.mount_info:
            mount_info.print_mounting()
        print("Mounting succeeded.")

        return True, lim_session

    def unmount_image(self) -> tuple[bool, LinImageMounterSession | None]:
        lim_manager = LinImageMounterManager()
        result = lim_manager.load_json(self.IMAGEINFO_JSON_PATH)
        if not result:
            return False, None

        print("Mounting info:")
        to_remove_sessions: list[int] = []
        for session_number, session in enumerate(lim_manager.sessions):
            if (not args.session_no or (session_number + 1 in args.session_no)) and (not args.session_id or (session.session_id in args.session_id)):
                session.print_mounting()

                result = self._run_umount(session)
                if not result:
                    return False, session

                result = self._run_dmsetup_remove(session)
                if not result:
                    return False, session

                result = self._run_losetup_detach(session)
                if not result:
                    return False, session

                result = self._run_fusermount_unmount(session)
                if not result:
                    return False, session

                result = self._remove_xmount_cache(session)
                if not result:
                    return False, session

                to_remove_sessions.append(session_number)

        for session_number in reversed(to_remove_sessions):
            del lim_manager.sessions[session_number]

        result = lim_manager.save_json(self.IMAGEINFO_JSON_PATH) if lim_manager.sessions else self._remove_image_info_json(self.IMAGEINFO_JSON_PATH)
        if not result:
            return False, None

        print("Unmounting succeeded.")

        return True, None

    def check_status(self) -> bool:
        if not os.path.exists(self.IMAGEINFO_JSON_PATH):
            print("No image is mounted.")
            return True

        lim_manager = LinImageMounterManager()
        result = lim_manager.load_json(self.IMAGEINFO_JSON_PATH)
        if not result:
            return False

        print("Current status:")
        for idx, session in enumerate(lim_manager.sessions):
            print(f"[Session Number: {idx + 1}]")
            session.print_info()

        return True

    def _run_cmd(self, cmd_line: list[str]) -> subprocess.CompletedProcess:
        debug_print(" ".join(cmd_line))
        result = subprocess.run(cmd_line, capture_output=True, text=True, encoding="utf-8", check=False)
        debug_print(f"return code: {result.returncode}")
        debug_print(f"stdout: {result.stdout}")
        debug_print(f"stderr: {result.stderr}")
        return result

    def _run_xmount(self, lim_session: LinImageMounterSession) -> bool:
        debug_print("===== Run Xmount =====")
        # Check if the xmount cache dir exists
        xmount_cache_dir = os.path.abspath(os.path.expanduser("~/.xmount-cache"))
        if os.path.isfile(xmount_cache_dir):
            print("xmount cache directory is a file.")
            return False

        os.makedirs(xmount_cache_dir, exist_ok=True)

        for image_info in lim_session.image_info:
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
            result = self._run_cmd(
                [self.CMD_XMOUNT, "--in", args.type, image_info.image, "--out", "vmdk", "--cache", xmount_cache_path, image_info.image_mountpoint],
            )
            if result.returncode != 0 or not os.path.ismount(image_info.image_mountpoint):
                print("Failed to run xmount.")
                return False

        return True

    def _run_kpartx(self, lim_session: LinImageMounterSession) -> bool:
        debug_print("===== Run Kpartx =====")
        for image_info in lim_session.image_info:
            raw_image_filename = os.path.splitext(os.path.basename(image_info.image))[0] + ".dd"
            xmount_image_path = os.path.join(image_info.image_mountpoint, raw_image_filename)
            image_info.xmount_image_path = xmount_image_path

            result = self._run_cmd([self.CMD_KPARTX, "-av", xmount_image_path])
            if result.returncode != 0:
                print("Failed to run kpartx.")
                return False

        return True

    def _run_loseup(self, lim_session: LinImageMounterSession, sleeptime=2) -> bool:
        debug_print("===== Run Losetup =====")
        # Wait for the device mapper devices to be created
        time.sleep(sleeptime)
        result = self._run_cmd([self.CMD_LOSETUP, "--json"])
        if result.returncode != 0:
            print("Failed to run losetup.")
            return False

        data = json.loads(result.stdout)
        for loopback_device in data["loopdevices"]:
            for image_info in lim_session.image_info:
                if loopback_device["back-file"] == image_info.xmount_image_path:
                    image_info.loopback_device = os.path.basename(loopback_device["name"])
                    break

        return True

    def _get_dev_map(self) -> dict[str, str]:
        dev_map: dict[str, str] = {}
        for file in os.listdir("/dev/mapper"):
            mapped_device_path = os.path.join("/dev/mapper", file)
            if file not in ("control",) and os.path.islink(mapped_device_path):
                dm_name = os.path.basename(os.readlink(mapped_device_path))
                if file not in dev_map and dm_name.startswith("dm-"):
                    dev_map[file] = dm_name

        return dev_map

    def _lsblk_recursive(self, device: dict, mount_info: list[MountInfo], dev_map: dict[str, str]) -> None:
        if device.get("children"):
            if device["name"] in dev_map:
                dm_name = dev_map[device["name"]]
                mount_info.append(MountInfo(device=device["name"], dm_name=dm_name, mountable=False, mountpoint=None, filesystem=""))

            for child in device["children"]:
                self._lsblk_recursive(child, mount_info, dev_map)

        elif device["name"] in dev_map:
            devices = [info.device for info in mount_info]
            if device["name"] not in devices:
                dm_name = dev_map[device["name"]]
                mount_info.append(MountInfo(device=device["name"], dm_name=dm_name, mountable=True, mountpoint=None, filesystem=""))

    def _run_lsblk(self, lim_session: LinImageMounterSession) -> bool:
        debug_print("===== Run Lsblk =====")
        dev_map = self._get_dev_map()

        result = self._run_cmd([self.CMD_LSBLK, "--json"])
        if result.returncode != 0:
            print("Failed to run lsblk.")
            return False

        data = json.loads(result.stdout)
        for device in data["blockdevices"]:
            for image_info in lim_session.image_info:
                if device["name"] == image_info.loopback_device:
                    self._lsblk_recursive(device, lim_session.mount_info, dev_map)
                    break

        return True

    def _run_blkid(self, lim_session: LinImageMounterSession) -> bool:
        debug_print("===== Run Blkid =====")
        result = self._run_cmd([self.CMD_BLKID])
        if result.returncode != 0:
            print("Failed to run blkid.")
            return False

        for mount_info in lim_session.mount_info:
            for line in result.stdout.splitlines():
                device = line.split(": ")[0]
                device_info = line.split(": ")[1]
                try:
                    if device.endswith(mount_info.device):
                        mount_info.filesystem = {k: v.strip('"') for k, v in [field.split("=") for field in device_info.split()]}["TYPE"]
                        if mount_info.filesystem.startswith("fat"):
                            mount_info.filesystem = "vfat"
                        elif mount_info.filesystem in ("swap", "LVM2_member"):
                            mount_info.mountable = False
                        debug_print(f"Device: {device}, Filesystem: {mount_info.filesystem}, Mountable: {mount_info.mountable}")
                        break
                except KeyError:
                    debug_print(f"'{line}' has no TYPE field.")
                    continue

        return True

    def _run_mount(self, lim_session: LinImageMounterSession) -> bool:
        debug_print("===== Run Mount =====")
        for mount_info in lim_session.mount_info:
            if mount_info.mountable and mount_info.mountpoint is None:
                dm_path = os.path.join("/dev", mount_info.dm_name)
                device_mountpoint = os.path.join(lim_session.mountpoint_base, mount_info.device)

                if os.path.isfile(device_mountpoint):
                    print(f"Mountpoint {device_mountpoint} is a file.")
                    return False

                os.makedirs(device_mountpoint, exist_ok=True)

                mount_option = "rw" if args.read_write else "ro"
                result = self._run_cmd([self.CMD_MOUNT, "-t", mount_info.filesystem, "-o", mount_option, dm_path, device_mountpoint])
                if result.returncode != 0 or not os.path.ismount(device_mountpoint):
                    print(f"Failed to mount {dm_path} to {device_mountpoint}.")
                    return False

                mount_info.mountpoint = device_mountpoint

        return True

    def _run_umount(self, lim_session: LinImageMounterSession) -> bool:
        debug_print("===== Run Umount =====")
        for mount_info in lim_session.mount_info:
            if mount_info.mountpoint:
                result = self._run_cmd([self.CMD_UMOUNT, mount_info.mountpoint])
                if result.returncode != 0:
                    debug_print(f"Failed to unmount {mount_info.mountpoint}.")
                    return False

                try:
                    shutil.rmtree(mount_info.mountpoint)
                    debug_print(f"Removed mountpoint: {mount_info.mountpoint}")
                except OSError as e:
                    print(f"Failed to remove a mountpoint {mount_info.mountpoint}: {e}")
                    return False

        return True

    def _run_dmsetup_remove(self, lim_session: LinImageMounterSession) -> bool:
        debug_print("===== Run Dmsetup Remove =====")
        reverse_mount_info = sorted(lim_session.mount_info, key=lambda x: x.dm_name, reverse=True)
        for mount_info in reverse_mount_info:
            device_map_path = os.path.join("/dev", mount_info.dm_name)
            result = self._run_cmd([self.CMD_DMSETUP, "remove", device_map_path])
            if result.returncode != 0:
                print(f"Failed to remove device map {device_map_path}.")
                return False

        return True

    def _run_losetup_detach(self, lim_session: LinImageMounterSession) -> bool:
        debug_print("===== Run Losetup Detach =====")
        for image_info in lim_session.image_info:
            loopback_device_path = os.path.join("/dev", image_info.loopback_device)
            result = self._run_cmd([self.CMD_LOSETUP, "-d", loopback_device_path])
            if result.returncode != 0:
                print(f"Failed to detach loopback device {loopback_device_path}.")
                return False

        return True

    def _run_fusermount_unmount(self, lim_session: LinImageMounterSession) -> bool:
        debug_print("===== Run Fusermount Unmount =====")
        for image_info in lim_session.image_info:
            result = self._run_cmd([self.CMD_FUSERMOUNT, "-u", image_info.image_mountpoint])
            if result.returncode != 0:
                print(f"Failed to unmount {image_info.image_mountpoint}.")
                return False

            try:
                shutil.rmtree(image_info.image_mountpoint)
                print(f"Removed image mountpoint: {image_info.image_mountpoint}")
            except OSError as e:
                print(f"Failed to remove image mountpoint {image_info.image_mountpoint}: {e}")
                return False

        return True

    def _remove_xmount_cache(self, lim_session: LinImageMounterSession) -> bool:
        debug_print("===== Remove Xmount Cache =====")
        try:
            for image_info in lim_session.image_info:
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

    def _remove_image_info_json(self, image_info_json_path: str) -> bool:
        debug_print("===== Remove Image Info JSON =====")
        try:
            os.remove(os.path.abspath(os.path.expanduser(image_info_json_path)))
            debug_print(f"Removed image info JSON file: {image_info_json_path}")
        except OSError as e:
            print(f"Failed to remove image info JSON file: {e}")
            return False
        else:
            return True


def comma_separated_integers(value: str) -> list[int]:
    try:
        return [int(v.strip()) for v in value.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError("List must be comma-separated integers.")


def comma_separated_strings(value: str) -> list[str]:
    try:
        return [v.strip() for v in value.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError("List must be comma-separated strings.")


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
    parser.add_argument(
        "--session-no",
        type=comma_separated_integers,
        default=[],
        help="Specify comma-separated session numbers to unmount.",
    )
    parser.add_argument(
        "--session-id",
        type=comma_separated_strings,
        default=[],
        help="Specify comma-separated session ids to unmount.",
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


def main() -> None:
    if not platform_is_linux():
        print("This script only supports Linux.")
        sys.exit(1)

    if args.session_no and args.session_id:
        print("Can not specify both session number and session id.")
        sys.exit(1)

    if not check_root_privilege():
        print("This script requires root privilege.")
        sys.exit(1)

    lim_manager = LinImageMounterManager()
    if not lim_manager.check_dependencies():
        print("Please install the required dependencies.")
        sys.exit(1)

    result = False
    lim_session = None
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
        result, lim_session = lim_manager.mount_image(list(seen_images), args.mountpoint_base)
    elif args.command == "unmount":
        result, lim_session = lim_manager.unmount_image()
    elif args.command == "status":
        result = lim_manager.check_status()
    else:
        print("Invalid command.")
        sys.exit(1)

    if not result:
        print("Failed to execute the command.")
        if args.debug and lim_session is not None:
            lim_session.print_info()
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    args = parse_arguments()
    main()
