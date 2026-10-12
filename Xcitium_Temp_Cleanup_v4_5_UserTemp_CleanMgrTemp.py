# -*- coding: utf-8 -*-
"""Xcitium user-temp cleanup + Windows CleanMgr Temporary Files.

Targets are intentionally narrow:
  1) Every discovered user profile\\AppData\\Local\\Temp (Python cleaner).
  2) CleanMgr handler named "Temporary Files" via temporary /sagerun:65 profile.

Mounted-image folders such as NLTmpMnt are never traversed by the Python cleaner.
CleanMgr uses Windows' own Temporary Files handler and its own LastAccess policy;
it does not obey MinAgeHours. Registry StateFlags0065 values are restored after run.
"""

import ctypes
import fnmatch
import json
import ntpath
import os
import re
import shutil
import subprocess
import stat
import sys
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime


SCRIPT_NAME = "Xcitium Windows Temp Cleanup"
SCRIPT_VERSION = "4.5"
DEFAULTS = {
    "MinAgeHours": 24,
    "DryRun": False,             # Xcitium: live cleanup if not overridden
    "CleanWERArchive": False,
    "CleanBrowserCaches": False,
    "RunCleanMgr": True,         # configure a safe temporary profile and run /sagerun:65
    "MaxRuntimeSeconds": 900,
}
MAX_ERROR_LINES = 40
MAX_DEPTH = 128
MAX_ITEM_LOG_LINES = 100000   # per-item audit lines per run; counters continue after this
LOG_RETENTION = 10            # audit log files kept
LOG_SUBDIR = ("Logs", "XcitiumTempCleanup")
# Only these folder names may ever be a cleanup root (checked on the last path component).
ALLOWED_TARGET_NAMES = frozenset(("temp", "reportqueue", "reportarchive",
                                  "cache", "code cache", "gpucache", "cache2"))
# Entries (files or folders, any depth) whose NAME matches are never touched and
# their subtree is retained. Starting point only: extend for your own EDR/AV/RMM stack.
PROTECTED_NAME_PATTERNS = (
    "$*", "config.msi", "*.sys", "*.cat",
    "*xcitium*", "*comodo*", "cmdagent*", "itsm*",
    "*defender*", "mpcmdrun*", "mpsigstub*", "*windowsupdate*", "*wuauserv*", "msdtc*",
    "ccmsetup*", "ccmcache*", "*sophos*", "*crowdstrike*", "csagent*", "*sentinel*",
    "*carbonblack*", "*cylance*", "*trendmicro*", "*symantec*", "*mcafee*",
    "*kaspersky*", "*bitdefender*", "*malwarebytes*", "*tanium*", "*intune*",
    # NTLite image mounts can expose a full Windows system tree under user Temp.
    # Do not descend into, remove or try to clean those folders.
    "nltmpmnt*",
)
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000
PROCESS_MODE_BACKGROUND_END = 0x00200000
TH32CS_SNAPPROCESS = 0x2
ERROR_NO_MORE_FILES = 18
BOOL = ctypes.c_int32
DWORD = ctypes.c_uint32
HANDLE = ctypes.c_void_p


class ConfigurationError(Exception):
    pass


class UnsafePath(Exception):
    pass


class CleanupTimeout(Exception):
    pass


def is_protected_name(name):
    lowered = name.lower()
    return any(fnmatch.fnmatchcase(lowered, pattern) for pattern in PROTECTED_NAME_PATTERNS)


def path_is_or_contains(parent, child):
    """True if parent == child or parent is an ancestor of child (case-insensitive)."""
    parent = ntpath.normcase(normalize_path(parent)).rstrip("\\")
    child = ntpath.normcase(normalize_path(child)).rstrip("\\")
    return child == parent or child.startswith(parent + "\\")


class ItemLog:
    """Per-item audit trail. Lives in an admin-only folder under <Windows>\\Logs."""
    def __init__(self):
        self.handle = None
        self.path = None
        self.lines = 0
        self.dropped = 0

    def open(self, windows_dir):
        try:
            directory = ntpath.join(windows_dir, *LOG_SUBDIR)
            os.makedirs(directory, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.path = ntpath.join(directory, "TempCleanup_{}_{}.log".format(stamp, os.getpid()))
            self.handle = open(self.path, "a", encoding="utf-8", errors="backslashreplace", buffering=1)
            self._rotate(directory)
        except OSError as exc:
            self.handle = None
            log("WARNING: Audit log unavailable ({}); per-item records will not be saved.".format(exc))

    def _rotate(self, directory):
        try:
            names = sorted(name for name in os.listdir(directory)
                           if name.startswith("TempCleanup_") and name.endswith(".log"))
            for name in names[:-LOG_RETENTION]:
                full = ntpath.join(directory, name)
                if not os.path.islink(full):
                    os.remove(full)
        except OSError as exc:
            log("WARNING: Audit log rotation failed: {}".format(exc))

    def write(self, action, path, detail=""):
        if self.handle is None:
            return
        if self.lines >= MAX_ITEM_LOG_LINES:
            self.dropped += 1
            return
        self.lines += 1
        try:
            self.handle.write("{}\t{}\t{}\t{}\n".format(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"), action, path, detail))
        except (OSError, ValueError):
            self.handle = None

    def close(self):
        if self.handle is not None:
            if self.dropped:
                self.write("NOTE", "-", "{} further records suppressed".format(self.dropped))
            try:
                self.handle.close()
            except OSError:
                pass
            self.handle = None


def log(message):
    line = "[{}] {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message)
    try:
        print(line, flush=True)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        print(line.encode(encoding, "backslashreplace").decode(encoding), flush=True)


def human_bytes(value):
    size = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return "{:.2f} {}".format(size, unit)
        size /= 1024


def parse_bool(name, value):
    if value is None or str(value).strip() == "":
        return DEFAULTS[name]
    text = str(value).strip().lower()
    if text in ("true", "1", "yes", "on", "enabled"):
        return True
    if text in ("false", "0", "no", "off", "disabled"):
        return False
    raise ConfigurationError("{} must be true or false; received {!r}".format(name, value))


def parse_int(name, value, minimum, maximum):
    if value is None or str(value).strip() == "":
        return DEFAULTS[name]
    try:
        number = int(str(value).strip())
    except (ValueError, TypeError):
        raise ConfigurationError("{} must be an integer".format(name))
    if not minimum <= number <= maximum:
        raise ConfigurationError("{} must be between {} and {}".format(name, minimum, maximum))
    return number


def load_settings():
    # Literal calls match Xcitium's documented parameter declaration format.
    # Do not replace them with getParameter(name) inside a generic wrapper.
    try:
        itsm  # noqa: F821 -- injected by Xcitium, not an installable dependency
    except NameError:
        # Fail-safe for local execution: require explicit --clean; avoid
        # unexpectedly deleting files merely by opening the script.
        settings = dict(DEFAULTS)
        settings["DryRun"] = True
        args = sys.argv[1:]
        allowed = ("--clean", "--dry-run", "--no-cleanmgr")
        unknown = [arg for arg in args if arg not in allowed]
        if unknown or ("--clean" in args and "--dry-run" in args):
            raise ConfigurationError("Allowed standalone options: --clean, --dry-run, --no-cleanmgr")
        if "--clean" in args:
            settings["DryRun"] = False
        if "--no-cleanmgr" in args:
            settings["RunCleanMgr"] = False
        log("Xcitium API unavailable; standalone mode: {}.".format(
            "DRY RUN" if settings["DryRun"] else "LIVE CLEAN"))
        return settings
    try:
        MinAgeHours = itsm.getParameter('MinAgeHours')
        DryRun = itsm.getParameter('DryRun')
        CleanWERArchive = itsm.getParameter('CleanWERArchive')
        CleanBrowserCaches = itsm.getParameter('CleanBrowserCaches')
        RunCleanMgr = itsm.getParameter('RunCleanMgr')
        MaxRuntimeSeconds = itsm.getParameter('MaxRuntimeSeconds')
    except Exception as exc:
        raise ConfigurationError("Xcitium parameter read failed; cleanup cancelled: {}".format(exc))
    return {
        "MinAgeHours": parse_int("MinAgeHours", MinAgeHours, 1, 8760),
        "DryRun": parse_bool("DryRun", DryRun),
        "CleanWERArchive": parse_bool("CleanWERArchive", CleanWERArchive),
        "CleanBrowserCaches": parse_bool("CleanBrowserCaches", CleanBrowserCaches),
        "RunCleanMgr": parse_bool("RunCleanMgr", RunCleanMgr),
        "MaxRuntimeSeconds": parse_int("MaxRuntimeSeconds", MaxRuntimeSeconds, 60, 7200),
    }


def normalize_path(path):
    """Accept absolute DOS-drive paths only; reject UNC, devices and streams."""
    path = str(path).replace("/", "\\")
    if path.startswith("\\\\?\\"):
        path = path[4:]
    drive, tail = ntpath.splitdrive(path)
    if (len(drive) != 2 or not drive[0].isalpha() or drive[1] != ":"
            or not tail.startswith("\\") or ":" in tail or "\x00" in path):
        raise UnsafePath("Not an absolute local drive path: {!r}".format(path))
    parts = [part for part in tail.split("\\") if part]
    if any(part in (".", "..") or part.endswith((".", " ")) for part in parts):
        raise UnsafePath("Ambiguous path component: {!r}".format(path))
    return ntpath.normpath(drive.upper() + tail)


def extended_path(path):
    return "\\\\?\\" + normalize_path(path)


def same_path(first, second):
    return ntpath.normcase(normalize_path(first)) == ntpath.normcase(normalize_path(second))


def is_inside(path, root):
    path = ntpath.normcase(normalize_path(path))
    root = ntpath.normcase(normalize_path(root))
    return path != root and path.startswith(root.rstrip("\\") + "\\")


def ancestors(path):
    path = normalize_path(path)
    result = [path[:3]]
    current = path[:3]
    for component in path[3:].split("\\"):
        if component:
            current = ntpath.join(current, component)
            result.append(current)
    return result


class FILETIME(ctypes.Structure):
    _fields_ = [("low", DWORD), ("high", DWORD)]


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("attributes", DWORD), ("creation", FILETIME), ("access", FILETIME),
        ("modified", FILETIME), ("volume", DWORD), ("size_high", DWORD),
        ("size_low", DWORD), ("links", DWORD), ("index_high", DWORD),
        ("index_low", DWORD),
    ]


class FILE_DISPOSITION_INFO(ctypes.Structure):
    _fields_ = [("DeleteFile", ctypes.c_ubyte)]  # Win32 BOOLEAN, not BOOL


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", DWORD), ("cntUsage", DWORD), ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", DWORD),
        ("cntThreads", DWORD), ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def filetime_seconds(value):
    return ((int(value.high) << 32) | int(value.low)) / 10000000.0 - 11644473600.0


class OpenedItem:
    def __init__(self, fs, handle, info):
        self.fs = fs
        self.handle = handle
        self.info = info
        self.size = (int(info.size_high) << 32) | int(info.size_low)
        self.created = filetime_seconds(info.creation)
        self.modified = filetime_seconds(info.modified)
        # FILETIME 0 means "unknown"; it must never be read as "very old".
        self.times_valid = bool(info.creation.low or info.creation.high) and \
            bool(info.modified.low or info.modified.high)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.fs.close(self.handle)
        self.handle = None


class WindowsFileSystem:
    """Small Win32 adapter; deletion and validation refer to the same handle."""
    def __init__(self):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._bind("CreateFileW", [ctypes.c_wchar_p, DWORD, DWORD, ctypes.c_void_p,
                                   DWORD, DWORD, HANDLE], HANDLE)
        self._bind("CloseHandle", [HANDLE], BOOL)
        self._bind("GetFileInformationByHandle", [HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)], BOOL)
        self._bind("GetFinalPathNameByHandleW", [HANDLE, ctypes.c_wchar_p, DWORD, DWORD], DWORD)
        self._bind("SetFileInformationByHandle", [HANDLE, ctypes.c_int32, ctypes.c_void_p, DWORD], BOOL)
        self._bind("GetDriveTypeW", [ctypes.c_wchar_p], DWORD)
        self._bind("CreateMutexW", [ctypes.c_void_p, BOOL, ctypes.c_wchar_p], HANDLE)
        self._bind("WaitForSingleObject", [HANDLE, DWORD], DWORD)
        self._bind("ReleaseMutex", [HANDLE], BOOL)
        self._bind("GetSystemWindowsDirectoryW", [ctypes.c_wchar_p, DWORD], DWORD)
        self._bind("CreateToolhelp32Snapshot", [DWORD, DWORD], HANDLE)
        self._bind("Process32FirstW", [HANDLE, ctypes.POINTER(PROCESSENTRY32W)], BOOL)
        self._bind("Process32NextW", [HANDLE, ctypes.POINTER(PROCESSENTRY32W)], BOOL)
        self._bind("GetCurrentProcess", [], HANDLE)
        self._bind("SetPriorityClass", [HANDLE, DWORD], BOOL)
        self.invalid_handle = ctypes.c_void_p(-1).value
        self._path_buffer = ctypes.create_unicode_buffer(32768)  # reused: single-threaded
        self._drive_ok = {}

    def _bind(self, name, argtypes, restype):
        function = getattr(self.kernel, name)
        function.argtypes = argtypes
        function.restype = restype

    def close(self, handle):
        if handle is not None:
            self.kernel.CloseHandle(handle)

    def windows_directory(self):
        """Authoritative Windows directory (API, not the SystemRoot environment variable)."""
        buffer = ctypes.create_unicode_buffer(520)
        count = self.kernel.GetSystemWindowsDirectoryW(buffer, len(buffer))
        if not count or count >= len(buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        return normalize_path(buffer.value)

    def background_mode(self, enable):
        """Lower CPU/IO/memory priority for this process while scanning (best effort)."""
        flag = PROCESS_MODE_BACKGROUND_BEGIN if enable else PROCESS_MODE_BACKGROUND_END
        return bool(self.kernel.SetPriorityClass(self.kernel.GetCurrentProcess(), flag))

    def running_process_names(self):
        """Lower-case image names of all processes (no subprocess, no codepage issues)."""
        snapshot = self.kernel.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot in (None, self.invalid_handle):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            names = set()
            if not self.kernel.Process32FirstW(snapshot, ctypes.byref(entry)):
                raise ctypes.WinError(ctypes.get_last_error())
            while True:
                names.add(entry.szExeFile.lower())
                if not self.kernel.Process32NextW(snapshot, ctypes.byref(entry)):
                    error = ctypes.get_last_error()
                    if error != ERROR_NO_MORE_FILES:
                        raise ctypes.WinError(error)
                    break
        finally:
            self.close(snapshot)
        if "svchost.exe" not in names:
            raise RuntimeError("Process snapshot looks incomplete; browser cleanup cancelled.")
        return names

    def open_item(self, path, directory=False, delete_access=False):
        path = normalize_path(path)
        root = path[:3].upper()
        fixed = self._drive_ok.get(root)
        if fixed is None:
            fixed = self.kernel.GetDriveTypeW(root) == 3  # DRIVE_FIXED
            self._drive_ok[root] = fixed
        if not fixed:
            raise UnsafePath("Only local fixed drives are allowed: {}".format(path))
        access = 0x80 | (0x10000 if delete_access else 0)  # READ_ATTRIBUTES | DELETE
        # No SHARE_DELETE: pin names. Deleteable files also deny concurrent writes.
        share = 0x1 | (0x2 if directory or not delete_access else 0)
        handle = self.kernel.CreateFileW(extended_path(path), access, share, None,
                                         3, 0x02000000 | 0x00200000, None)
        if handle in (None, self.invalid_handle):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = BY_HANDLE_FILE_INFORMATION()
            if not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                raise UnsafePath("Reparse point/junction: {}".format(path))
            if bool(info.attributes & FILE_ATTRIBUTE_DIRECTORY) != directory:
                raise UnsafePath("Item type changed: {}".format(path))
            buffer = self._path_buffer
            count = self.kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
            if not count:
                raise ctypes.WinError(ctypes.get_last_error())
            if count >= len(buffer) or not same_path(path, buffer.value):
                raise UnsafePath("Resolved path differs from requested path: {}".format(path))
            return OpenedItem(self, handle, info)
        except BaseException:
            self.close(handle)
            raise

    @contextmanager
    def pin_parents(self, root):
        with ExitStack() as stack:
            # Target itself is opened by walk(); all its ancestors stay pinned.
            for parent in ancestors(root)[:-1]:
                stack.enter_context(self.open_item(parent, directory=True))
            yield

    def mark_delete(self, item):
        disposition = FILE_DISPOSITION_INFO(1)
        if not self.kernel.SetFileInformationByHandle(
                item.handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
            raise ctypes.WinError(ctypes.get_last_error())

    @contextmanager
    def single_instance(self):
        handle = self.kernel.CreateMutexW(None, False, "Global\\Xcitium.ModernTempCleanup.v4")
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        acquired = False
        try:
            result = self.kernel.WaitForSingleObject(handle, 0)
            if result == 258:  # WAIT_TIMEOUT
                raise CleanupTimeout("Another cleanup instance is already running.")
            if result not in (0, 128):  # WAIT_OBJECT_0, WAIT_ABANDONED
                raise ctypes.WinError(ctypes.get_last_error())
            acquired = True
            yield
        finally:
            if acquired:
                self.kernel.ReleaseMutex(handle)
            self.close(handle)


class Cleaner:
    def __init__(self, settings, fs, critical_paths, own_paths, item_log):
        self.settings = settings
        self.fs = fs
        self.critical_paths = critical_paths   # a cleanup root may never be/contain these
        self.own_paths = own_paths             # script/log files: never deleted
        self.items = item_log
        self.cutoff = time.time() - settings["MinAgeHours"] * 3600
        self.deadline = time.monotonic() + settings["MaxRuntimeSeconds"]
        self.error_lines = 0
        self.seen_targets = set()
        self.mounted_image_candidates = set()  # NTLite-style temp mounts; never walk them
        self.stats = dict.fromkeys((
            "targets", "missing_targets", "rejected_targets", "scanned_entries",
            "deleted_files", "deleted_dirs", "deleted_bytes", "would_delete_files",
            "would_delete_dirs", "would_delete_bytes", "skipped_recent", "skipped_reparse",
            "skipped_readonly", "skipped_locked", "skipped_denied", "skipped_changed",
            "skipped_browser_targets", "skipped_protected", "errors",
        ), 0)

    def check_time(self):
        if time.monotonic() >= self.deadline:
            raise CleanupTimeout("MaxRuntimeSeconds reached; cleanup stopped between operations.")

    def record(self, action, path, detail=""):
        self.items.write(action, path, detail)

    def is_protected(self, child, name):
        if is_protected_name(name):
            return True
        return any(path_is_or_contains(child, own) for own in self.own_paths)

    def warn(self, path, exc):
        if self.error_lines < MAX_ERROR_LINES:
            log("WARNING: {} | {}".format(path, exc))
        elif self.error_lines == MAX_ERROR_LINES:
            log("WARNING: Further individual warnings suppressed; see summary counters.")
        self.error_lines += 1

    def handle_error(self, path, exc, scanning=False):
        code = getattr(exc, "winerror", None)
        if code not in (2, 3, 145):
            self.record("SKIP_ERROR", path, "winerror={} {}".format(code, exc))
        if code in (2, 3):
            self.stats["skipped_changed"] += 1
        elif code in (32, 33):
            self.stats["skipped_locked"] += 1
            if scanning:
                self.stats["errors"] += 1
            self.warn(path, exc)
        elif code == 5:
            self.stats["skipped_denied"] += 1
            if scanning:
                self.stats["errors"] += 1
            self.warn(path, exc)
        elif code == 145:  # directory gained entries during cleanup
            self.stats["skipped_changed"] += 1
        else:
            self.stats["errors"] += 1
            self.warn(path, exc)

    def old_enough(self, item):
        return item.times_valid and max(item.created, item.modified) <= self.cutoff

    def clean_file(self, path, root):
        self.check_time()
        if not is_inside(path, root):
            raise UnsafePath("File is outside the cleanup target: {}".format(path))
        try:
            with self.fs.open_item(path, delete_access=True) as item:
                if item.info.attributes & FILE_ATTRIBUTE_READONLY:
                    self.stats["skipped_readonly"] += 1
                    self.record("SKIP_READONLY", path)
                    return True
                if not self.old_enough(item):
                    self.stats["skipped_recent"] += 1
                    return True
                if self.settings["DryRun"]:
                    self.record("WOULD_DELETE", path, "size={}".format(item.size))
                    self.stats["would_delete_files"] += 1
                    self.stats["would_delete_bytes"] += item.size
                else:
                    self.record("DELETE", path, "size={}".format(item.size))
                    self.fs.mark_delete(item)
                    self.stats["deleted_files"] += 1
                    self.stats["deleted_bytes"] += item.size
                return False
        except UnsafePath as exc:
            self.stats["skipped_reparse"] += 1
            self.record("SKIP_UNSAFE", path, str(exc))
            self.warn(path, exc)
        except OSError as exc:
            self.handle_error(path, exc)
        return True

    def walk(self, path, root, remove_directory=False, depth=0):
        self.check_time()
        if depth > MAX_DEPTH:
            self.stats["errors"] += 1
            self.warn(path, "Directory depth limit reached; subtree retained.")
            return True
        if not same_path(path, root) and not is_inside(path, root):
            raise UnsafePath("Directory is outside the cleanup target: {}".format(path))
        try:
            with self.fs.open_item(path, directory=True, delete_access=remove_directory) as directory:
                old_directory = self.old_enough(directory)  # before deleting any children
                remaining = False
                with os.scandir(extended_path(path)) as entries:
                    for entry in entries:
                        self.check_time()
                        self.stats["scanned_entries"] += 1
                        try:
                            child = normalize_path(entry.path)
                            # Check protected names BEFORE any stat/open/traversal. NTLite's
                            # NLTmpMnt is a mounted Windows image inside a Temp folder,
                            # which may contain many protected files and junctions.
                            if self.is_protected(child, entry.name):
                                self.stats["skipped_protected"] += 1
                                self.record("SKIP_PROTECTED", child)
                                if entry.name.lower().startswith("nltmpmnt"):
                                    self.mounted_image_candidates.add(child)
                                    self.record("SKIP_MOUNTED_IMAGE", child, "NTLite mount name")
                                    log("Mounted-image directory excluded from cleanup: {}".format(child))
                                remaining = True
                                continue
                            info = entry.stat(follow_symlinks=False)
                            if (stat.S_ISLNK(info.st_mode) or
                                    getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT):
                                self.stats["skipped_reparse"] += 1
                                self.record("SKIP_REPARSE", child)
                                remaining = True
                            elif stat.S_ISDIR(info.st_mode):
                                remaining = self.walk(child, root, True, depth + 1) or remaining
                            elif stat.S_ISREG(info.st_mode):
                                # Fast skips avoid opening very recent files. Any deletion
                                # still rechecks age/type/path on the actual Windows handle.
                                created = getattr(info, "st_birthtime", None)  # 3.12+
                                if created is None:
                                    created = info.st_ctime  # creation time on Windows < 3.12
                                if getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_READONLY:
                                    self.stats["skipped_readonly"] += 1
                                    self.record("SKIP_READONLY", child)
                                    remaining = True
                                elif (min(created, info.st_mtime) <= 0
                                      or max(created, info.st_mtime) > self.cutoff):
                                    self.stats["skipped_recent"] += 1
                                    remaining = True
                                else:
                                    remaining = self.clean_file(child, root) or remaining
                            else:
                                self.stats["skipped_changed"] += 1
                                self.record("SKIP_SPECIAL", child)
                                remaining = True
                        except UnsafePath as exc:
                            self.stats["skipped_reparse"] += 1
                            self.record("SKIP_UNSAFE", entry.path, str(exc))
                            self.warn(entry.path, exc)
                            remaining = True
                        except OSError as exc:
                            self.handle_error(entry.path, exc, scanning=True)
                            remaining = True
                if remove_directory and old_directory and not remaining:
                    if self.settings["DryRun"]:
                        self.record("WOULD_DELETE_DIR", path)
                        self.stats["would_delete_dirs"] += 1
                    else:
                        self.record("DELETE_DIR", path)
                        self.fs.mark_delete(directory)
                        self.stats["deleted_dirs"] += 1
                    return False
                return True
        except UnsafePath as exc:
            self.stats["skipped_reparse"] += 1
            self.record("SKIP_UNSAFE", path, str(exc))
            if not remove_directory:
                self.stats["rejected_targets"] += 1
                self.stats["errors"] += 1
            self.warn(path, exc)
        except OSError as exc:
            if not remove_directory and getattr(exc, "winerror", None) in (2, 3):
                self.stats["missing_targets"] += 1
            else:
                self.handle_error(path, exc, scanning=True)
        return True

    def clean_target(self, path, label):
        self.check_time()
        try:
            path = normalize_path(path)
            if len(ancestors(path)) < 3:
                raise UnsafePath("Cleanup target is too broad: {}".format(path))
            if ntpath.basename(path).lower() not in ALLOWED_TARGET_NAMES:
                raise UnsafePath("Cleanup target name is not allow-listed: {}".format(path))
            for critical in self.critical_paths:
                if path_is_or_contains(path, critical):
                    raise UnsafePath("Cleanup target is, or contains, a protected system folder: {}".format(path))
            key = ntpath.normcase(path)
            if key in self.seen_targets:
                return
            self.seen_targets.add(key)
            with self.fs.pin_parents(path):
                self.stats["targets"] += 1
                log("Target [{}]: {}".format(label, path))
                self.record("TARGET", path, label)
                self.walk(path, path)
        except UnsafePath as exc:
            self.stats["rejected_targets"] += 1
            self.stats["errors"] += 1
            self.warn(path, exc)
        except OSError as exc:
            if getattr(exc, "winerror", None) in (2, 3):
                self.stats["missing_targets"] += 1
            else:
                self.handle_error(path, exc, scanning=True)


def expand_system_vars(value, system_drive):
    """Expand only %SystemDrive% (from the Windows directory, not the environment)."""
    value = re.sub(r"%SystemDrive%", lambda _m: system_drive, value, flags=re.IGNORECASE)
    if "%" in value:
        raise UnsafePath("Unresolved variable in path: {!r}".format(value))
    return value


def get_program_data(system_drive):
    import winreg
    default = system_drive + "\\ProgramData"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            raw, _ = winreg.QueryValueEx(key, "ProgramData")
        return normalize_path(expand_system_vars(str(raw), system_drive))
    except (OSError, UnsafePath):
        return default


def get_user_profiles(fs, users_root, system_drive):
    import winreg  # loaded only after the Windows/runtime check
    registry_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    profiles = set()
    failed = False
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as root:
            for index in range(winreg.QueryInfoKey(root)[0]):
                sid = winreg.EnumKey(root, index)
                if sid in ("S-1-5-18", "S-1-5-19", "S-1-5-20") or sid.endswith(".bak"):
                    continue
                try:
                    with winreg.OpenKey(root, sid, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                        raw, _ = winreg.QueryValueEx(key, "ProfileImagePath")
                    profile = normalize_path(expand_system_vars(str(raw), system_drive))
                    if "\\windows\\serviceprofiles\\" not in profile.lower() + "\\":
                        profiles.add(profile)
                except (OSError, UnsafePath) as exc:
                    failed = True
                    log("WARNING: Cannot read user profile {}: {}".format(sid, exc))
    except OSError as exc:
        failed = True
        log("WARNING: ProfileList unavailable; using Users folder fallback: {}".format(exc))
    if not profiles:
        excluded = {"all users", "default", "default user", "public", "defaultuser0"}
        try:
            users_root = normalize_path(users_root)
            with fs.pin_parents(users_root), fs.open_item(users_root, directory=True):
                with os.scandir(extended_path(users_root)) as entries:
                    for entry in entries:
                        info = entry.stat(follow_symlinks=False)
                        if (entry.name.lower() not in excluded and stat.S_ISDIR(info.st_mode)
                                and not getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT):
                            profiles.add(normalize_path(entry.path))
        except (OSError, UnsafePath) as exc:
            failed = True
            log("WARNING: Users fallback scan failed: {}".format(exc))
    return sorted(profiles, key=str.lower), failed


def browser_cache_paths(fs, profile):
    local = ntpath.join(profile, "AppData", "Local")
    browsers = (("chrome.exe", ntpath.join(local, "Google", "Chrome", "User Data")),
                ("msedge.exe", ntpath.join(local, "Microsoft", "Edge", "User Data")),
                ("firefox.exe", ntpath.join(local, "Mozilla", "Firefox", "Profiles")))
    result = []
    for process, directory in browsers:
        try:
            with fs.pin_parents(directory), fs.open_item(directory, directory=True):
                with os.scandir(extended_path(directory)) as entries:
                    for entry in entries:
                        info = entry.stat(follow_symlinks=False)
                        if (not stat.S_ISDIR(info.st_mode) or
                                getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT):
                            continue
                        if process == "firefox.exe":
                            names = ("cache2",)
                        elif entry.name == "Default" or entry.name.startswith("Profile "):
                            names = ("Cache", "Code Cache", "GPUCache")
                        else:
                            continue
                        for name in names:
                            result.append((process, ntpath.join(normalize_path(entry.path), name)))
        except OSError as exc:
            if getattr(exc, "winerror", None) not in (2, 3):
                raise
    return result


CLEANMGR_PROFILE = 65
CLEANMGR_FLAG = "StateFlags{:04d}".format(CLEANMGR_PROFILE)
CLEANMGR_REGISTRY_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
# Narrow, reviewable policy for corporate endpoints. Categories are Windows
# handler KEY NAMES, not translated UI labels. Missing categories are ignored.
# In particular, DO NOT enable Recycle Bin, Downloads, Previous Installations,
# Update Cleanup, device drivers, ESD, error memory dumps or AV/security logs.
CLEANMGR_SAFE_CATEGORIES = frozenset((
    "Temporary Files",
))


def available_cleanmgr_categories():
    """Discover present allowlisted categories without modifying the registry."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CLEANMGR_REGISTRY_PATH,
                        0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as root:
        names = [winreg.EnumKey(root, i) for i in range(winreg.QueryInfoKey(root)[0])]
    allowed = {category.lower() for category in CLEANMGR_SAFE_CATEGORIES}
    return sorted((name for name in names if name.lower() in allowed), key=str.lower)


def cleanmgr_categories():
    """Find all actually enabled handlers for profile 65 (including unsafe ones)."""
    import winreg
    selected = []
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CLEANMGR_REGISTRY_PATH, 0, access) as root:
        for index in range(winreg.QueryInfoKey(root)[0]):
            name = winreg.EnumKey(root, index)
            try:
                with winreg.OpenKey(root, name, 0, access) as entry:
                    value, kind = winreg.QueryValueEx(entry, CLEANMGR_FLAG)
                if kind == winreg.REG_DWORD and value == 2:
                    selected.append(name)
            except FileNotFoundError:
                pass
    return sorted(selected, key=str.lower)


def restore_cleanmgr_profile(snapshot):
    """Restore every original StateFlags0065, including absence and REG types."""
    import winreg
    access = winreg.KEY_READ | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
    failures = []
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CLEANMGR_REGISTRY_PATH, 0, access) as root:
        for name, original in reversed(snapshot):
            try:
                with winreg.OpenKey(root, name, 0, access) as entry:
                    if original is None:
                        try:
                            winreg.DeleteValue(entry, CLEANMGR_FLAG)
                        except FileNotFoundError:
                            pass
                    else:
                        value, kind = original
                        winreg.SetValueEx(entry, CLEANMGR_FLAG, 0, kind, value)
            except OSError as exc:
                failures.append("{}: {}".format(name, exc))
    if failures:
        raise OSError("Could not restore CleanMgr profile: " + "; ".join(failures[:5]))


def configure_cleanmgr_profile(allowed_categories=None):
    """Select only the explicitly allowlisted CleanMgr categories."""
    import winreg
    access = winreg.KEY_READ | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
    if allowed_categories is None:
        allowed_categories = CLEANMGR_SAFE_CATEGORIES
    allowed = {name.lower() for name in allowed_categories}
    if not allowed.issubset({name.lower() for name in CLEANMGR_SAFE_CATEGORIES}):
        raise ConfigurationError("Cannot enable non-allowlisted CleanMgr categories.")
    snapshot = []
    selected = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CLEANMGR_REGISTRY_PATH, 0, access) as root:
            names = [winreg.EnumKey(root, i) for i in range(winreg.QueryInfoKey(root)[0])]
            for name in names:
                with winreg.OpenKey(root, name, 0, access) as entry:
                    try:
                        previous = winreg.QueryValueEx(entry, CLEANMGR_FLAG)
                    except FileNotFoundError:
                        previous = None
                    snapshot.append((name, previous))
                    enabled = name.lower() in allowed
                    winreg.SetValueEx(entry, CLEANMGR_FLAG, 0, winreg.REG_DWORD, 2 if enabled else 0)
                    if enabled:
                        selected.append(name)
        if not selected:
            raise ConfigurationError("No allowlisted CleanMgr categories are installed.")
        # Fail closed if the registry does not reflect precisely our allowlist.
        if set(cleanmgr_categories()) != set(selected):
            raise ConfigurationError("CleanMgr profile verification mismatch; cleanup cancelled.")
        return sorted(selected, key=str.lower), snapshot
    except BaseException:
        if snapshot:
            try:
                restore_cleanmgr_profile(snapshot)
            except OSError as exc:
                log("ERROR: Failed to roll back partial CleanMgr profile: {}".format(exc))
        raise


def run_cleanmgr(settings, system_root, cleaner):
    """Configure/execute/restore profile; no /sageset GUI, no arbitrary categories."""
    result = {"enabled": settings["RunCleanMgr"], "profile": CLEANMGR_PROFILE,
              "status": "DISABLED", "exit_code": None, "selected_categories": [],
              "profile_restored": None}
    if not settings["RunCleanMgr"]:
        cleaner.record("CLEANMGR_DISABLED", "-")
        return result
    cleaner.check_time()
    try:
        categories = available_cleanmgr_categories()
    except OSError as exc:
        log("WARNING: Cannot inspect CleanMgr categories: {}".format(exc))
        cleaner.record("CLEANMGR_ERROR", "-", str(exc))
        cleaner.stats["errors"] += 1
        result["status"] = "PROFILE_CHECK_FAILED"
        return result
    # This build intentionally runs only the Windows "Temporary Files" handler.
    # Mounted-image protection remains enforced by the Python User Temp walker.
    result["selected_categories"] = categories
    if not categories:
        cleaner.stats["errors"] += 1
        cleaner.record("CLEANMGR_SKIPPED", "-", "No allowlisted categories present")
        result["status"] = "NO_SAFE_CATEGORIES"
        return result
    log("CleanMgr allowlisted categories ({}): {}".format(len(categories), ", ".join(categories)))
    if settings["DryRun"]:
        log("DRY RUN: Registry will NOT be changed and CleanMgr will NOT be launched.")
        cleaner.record("CLEANMGR_WOULD_RUN", "-", ", ".join(categories))
        result["status"] = "WOULD_RUN"
        return result

    path = ntpath.join(system_root, "Sysnative", "cleanmgr.exe")
    if not os.path.isfile(path):
        path = ntpath.join(system_root, "System32", "cleanmgr.exe")
    if not os.path.isfile(path):
        cleaner.record("CLEANMGR_ERROR", path, "Executable missing")
        cleaner.stats["errors"] += 1
        result["status"] = "NOT_INSTALLED"
        return result

    remaining = cleaner.deadline - time.monotonic()
    if remaining <= 0:
        raise CleanupTimeout("No time remains for CleanMgr.")
    try:
        categories, snapshot = configure_cleanmgr_profile(allowed_categories=categories)
    except (OSError, ConfigurationError) as exc:
        log("WARNING: CleanMgr profile setup failed: {}".format(exc))
        cleaner.record("CLEANMGR_ERROR", "-", str(exc))
        cleaner.stats["errors"] += 1
        result["status"] = "PROFILE_SETUP_FAILED"
        return result
    result["selected_categories"] = categories
    try:
        log("CleanMgr LIVE START: {} /sagerun:65".format(path))
        cleaner.record("CLEANMGR_START", path, "/sagerun:65")
        try:
            finished = subprocess.run([path, "/sagerun:65"], shell=False,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True,
                                      creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                      timeout=max(0.1, cleaner.deadline - time.monotonic()))
            result["exit_code"] = finished.returncode
            for stream, content in (("STDOUT", finished.stdout), ("STDERR", finished.stderr)):
                if content:
                    log("CleanMgr {}: {}".format(stream, content.strip()[:2000]))
            if finished.returncode != 0:
                result["status"] = "FAILED"
                cleaner.stats["errors"] += 1
                cleaner.record("CLEANMGR_FAILED", path, "exit_code={}".format(finished.returncode))
            else:
                result["status"] = "COMPLETED"
                cleaner.record("CLEANMGR_COMPLETE", path, "exit_code=0")
                log("CleanMgr finished (exit code 0; exact freed space is not reported).")
        except subprocess.TimeoutExpired:
            result["status"] = "TIMED_OUT"
            cleaner.record("CLEANMGR_TIMEOUT", path)
            cleaner.stats["errors"] += 1
            log("WARNING: CleanMgr timed out; direct process terminated, child processes may remain.")
        except OSError as exc:
            result["status"] = "START_FAILED"
            cleaner.record("CLEANMGR_ERROR", path, str(exc))
            cleaner.stats["errors"] += 1
            log("WARNING: CleanMgr could not start: {}".format(exc))
    finally:
        try:
            restore_cleanmgr_profile(snapshot)
            result["profile_restored"] = True
            cleaner.record("CLEANMGR_PROFILE_RESTORED", "-", "StateFlags0065")
        except OSError as exc:
            result["profile_restored"] = False
            cleaner.stats["errors"] += 1
            cleaner.record("CLEANMGR_PROFILE_RESTORE_FAILED", "-", str(exc))
            log("ERROR: CleanMgr profile was NOT fully restored: {}".format(exc))
    return result


def check_runtime():
    if os.name != "nt":
        raise ConfigurationError("Windows is required; nothing was cleaned.")
    if sys.version_info < (3, 6):
        raise ConfigurationError("Select a Python 3.6+ runtime for this procedure.")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ConfigurationError("Administrative rights required: run as Local System User.")


def main():
    log("{} v{} | Python {}".format(SCRIPT_NAME, SCRIPT_VERSION, sys.version.split()[0]))
    try:
        check_runtime()
        settings = load_settings()
        fs = WindowsFileSystem()
        system_root = fs.windows_directory()          # Win32 API, not %SystemRoot%
        drive_root = system_root[:3]
        system_drive = system_root[:2]
        program_data = get_program_data(system_drive)
    except Exception as exc:
        log("RESULT: FAILED | {}".format(exc))
        return 1
    critical_paths = [system_root, drive_root + "Users", program_data,
                      drive_root + "Program Files", drive_root + "Program Files (x86)",
                      drive_root + "$Recycle.Bin", drive_root + "System Volume Information",
                      drive_root + "Recovery", drive_root + "Boot"]
    own_paths = []
    for candidate in (globals().get("__file__"), sys.argv[0] if sys.argv else None):
        try:
            if candidate:
                own_paths.append(normalize_path(os.path.abspath(candidate)))
        except (OSError, UnsafePath, ValueError):
            pass
    item_log = ItemLog()
    item_log.open(system_root)
    if item_log.path:
        own_paths.append(item_log.path)
        log("Audit log: {}".format(item_log.path))
    cleaner = Cleaner(settings, fs, critical_paths, own_paths, item_log)
    before_free = None
    after_free = None
    result = 0
    try:
        before_free = shutil.disk_usage(drive_root).free
    except OSError as exc:
        log("WARNING: Free-space measurement unavailable: {}".format(exc))
    log("Mode: {} | MinAgeHours: {} | MaxRuntimeSeconds: {}".format(
        "DRY RUN" if settings["DryRun"] else "CLEAN", settings["MinAgeHours"], settings["MaxRuntimeSeconds"]))
    log("Scope: User AppData\\Local\\Temp + CleanMgr Temporary Files | RunCleanMgr: {} (profile 65)".format(
        settings["RunCleanMgr"]))
    cleanmgr_report = {"enabled": settings["RunCleanMgr"], "profile": CLEANMGR_PROFILE,
                       "status": "NOT_STARTED", "exit_code": None, "selected_categories": []}
    background = False
    try:
        background = fs.background_mode(True)
    except OSError:
        pass
    try:
        with fs.single_instance():
            # Intentionally clean ONLY per-user AppData\Local\Temp with Python.
            profiles, discovery_failed = get_user_profiles(fs, ntpath.join(drive_root, "Users"), system_drive)
            if discovery_failed:
                cleaner.stats["errors"] += 1
            log("User profiles found: {}".format(len(profiles)))
            for profile in profiles:
                cleaner.clean_target(ntpath.join(profile, "AppData", "Local", "Temp"), "User AppData Local Temp")

            # Intentionally run ONLY CleanMgr's "Temporary Files" handler.
            cleanmgr_report = run_cleanmgr(settings, system_root, cleaner)
    except CleanupTimeout as exc:
        log("WARNING: {}".format(exc))
        result = 2
    except Exception as exc:
        cleaner.stats["errors"] += 1
        log("ERROR: Unexpected failure: {}: {}".format(type(exc).__name__, exc))
        cleaner.record("FATAL", "-", "{}: {}".format(type(exc).__name__, exc))
        result = 1
    finally:
        if background:
            try:
                fs.background_mode(False)
            except OSError:
                pass
    if cleaner.stats["errors"] and result == 0:
        result = 2
    try:
        after_free = shutil.disk_usage(drive_root).free
    except OSError:
        pass
    status = "INCOMPLETE" if result == 2 else "FAILED" if result == 1 else "COMPLETED"
    if settings["DryRun"]:
        log("DRY RUN: {} eligible files, {} removable empty subdirectories, {} estimated data.".format(
            cleaner.stats["would_delete_files"], cleaner.stats["would_delete_dirs"],
            human_bytes(cleaner.stats["would_delete_bytes"])))
    else:
        log("CLEAN: {} file deletion requests, {} directory deletion requests, {} logical data.".format(
            cleaner.stats["deleted_files"], cleaner.stats["deleted_dirs"],
            human_bytes(cleaner.stats["deleted_bytes"])))
    delta = None if before_free is None or after_free is None else after_free - before_free
    if delta is not None:
        log("Observed system-drive free-space change: {} bytes (other activity may affect this).".format(delta))
    report = dict(cleaner.stats)
    report.update({"version": SCRIPT_VERSION, "status": status, "result_code": result,
                   "dry_run": settings["DryRun"], "min_age_hours": settings["MinAgeHours"],
                   "system_drive": drive_root, "free_bytes_before": before_free,
                   "free_bytes_after": after_free, "free_space_delta": delta,
                   "audit_log": item_log.path,
                   "cleanmgr": cleanmgr_report})
    log("RESULT: {} | errors: {} | locked: {} | denied: {} | reparse: {}".format(
        status, report["errors"], report["skipped_locked"], report["skipped_denied"], report["skipped_reparse"]))
    log("Protected-name skips: {} | readonly: {} | recent: {}".format(
        report["skipped_protected"], report["skipped_readonly"], report["skipped_recent"]))
    item_log.write("SUMMARY", "-", json.dumps(report, ensure_ascii=True, sort_keys=True))
    item_log.close()
    log("SUMMARY_JSON " + json.dumps(report, ensure_ascii=True, sort_keys=True))
    return result


# Execute even if an embedded runner supplies a nonstandard __name__.
XCITIUM_RESULT_CODE = main()
if XCITIUM_RESULT_CODE:
    raise RuntimeError("{} failed/incomplete (code {}); see procedure output.".format(
        SCRIPT_NAME, XCITIUM_RESULT_CODE))
