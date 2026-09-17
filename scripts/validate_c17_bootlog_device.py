#!/usr/bin/env python3
"""Read-only device evidence, with an explicit optional kmsg retention marker.

No reboot, module installation, raw partition writes, or pstore deletion.
Use --previous-marker only AFTER a separate, user-controlled reboot.
"""
import argparse
import gzip
import json
from pathlib import Path
import re
import subprocess
import uuid


def assess(kernel, params, driver, dmesg):
    expected = {"mem_size": 0x240000, "record_size": 0x40000,
                "console_size": 0x100000, "pmsg_size": 0x100000,
                "ftrace_size": 0, "max_reason": 5}
    checks = {"diagnostic_kernel": "C17LOG" in kernel,
              "builtin_owns_dt_device": driver.strip().endswith("/drivers/ramoops")}
    for key, value in expected.items():
        checks["ramoops_" + key] = params.get(key) == value
    ready = re.search(r"\[\s*([\d.]+)\].*C17_BOOTLOG_V2: early DT backend ready", dmesg)
    init = re.search(r"\[\s*([\d.]+)\].*Run /init as init process", dmesg)
    # Missing early messages means unknown, not success.
    checks["ready_before_userspace_init"] = (
        float(ready[1]) < float(init[1]) if ready and init else None)
    return checks


def parse_parameters(text):
    values = {}
    for line in text.splitlines():
        match = re.fullmatch(r"(\w+)=(-?(?:0x[0-9a-fA-F]+|\d+))", line.strip())
        if match:
            values[match[1]] = int(match[2], 0)
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--expect-v2", action="store_true")
    parser.add_argument("--write-marker", action="store_true")
    parser.add_argument("--previous-marker", type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    adb = [args.adb, "-s", args.serial]

    def call(parts):
        return subprocess.run(adb + parts, capture_output=True, timeout=45)

    def shell(name, command):
        r = call(["shell", command])
        text = r.stdout.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        (args.out / (name + ".txt")).write_text(text, encoding="utf-8")
        if r.returncode or r.stderr:
            (args.out / (name + ".stderr.txt")).write_bytes(r.stderr)
        return text

    identity = shell("identity", "id; uname -r; getprop ro.gsid.image_running; "
        "getprop ro.build.fingerprint; getenforce; cat /proc/sys/kernel/random/boot_id")
    if "uid=0(" not in identity:
        raise SystemExit("Root adb shell is required; no device state changed")
    kernel = shell("kernel", "uname -r")
    boot_id = shell("boot-id", "cat /proc/sys/kernel/random/boot_id").strip()
    params_text = shell("ramoops-parameters", "for f in /sys/module/ramoops/parameters/*; "
                        'do printf "%s=" "${f##*/}"; cat "$f"; done')
    params = parse_parameters(params_text)
    driver = shell("dt-driver", "readlink -f /sys/bus/platform/devices/soc:qcom_ramoops/driver")
    shell("modules", "cat /proc/modules")
    shell("reserved-memory", "cat /proc/iomem; cat /proc/cmdline")
    shell("pstore-list", "ls -la /sys/fs/pstore")
    shell("mountinfo", "cat /proc/self/mountinfo")
    dmesg = shell("dmesg", "dmesg")
    r = call(["exec-out", "cat", "/proc/config.gz"])
    (args.out / "config.gz").write_bytes(r.stdout)
    try:
        (args.out / "kernel.config").write_bytes(gzip.decompress(r.stdout))
    except (OSError, EOFError):
        pass
    pull = call(["pull", "/sys/fs/pstore", str(args.out / "pstore")])
    (args.out / "pstore-pull.txt").write_bytes(pull.stdout + pull.stderr)
    checks = assess(kernel, params, driver, dmesg)
    retention = {"status": "not_tested"}
    if args.previous_marker:
        previous = json.loads(args.previous_marker.read_text(encoding="utf-8"))
        if previous["boot_id"] == boot_id:
            retention = {"status": "not_tested_same_boot"}
        elif pull.returncode:
            retention = {"status": "inconclusive_pstore_pull_failed"}
        else:
            marker = previous["marker"].encode("ascii")
            found = [str(p.relative_to(args.out)) for p in (args.out / "pstore").rglob("*")
                     if p.is_file() and marker in p.read_bytes()]
            retention = {"status": "pass" if found else "marker_not_found", "files": found}
    if args.write_marker:
        if not args.expect_v2 or not all(v is True for v in checks.values()):
            raise SystemExit("Refusing marker test until V2 early-start checks all pass")
        marker = "C17_RETENTION_" + uuid.uuid4().hex
        command = "printf '<5>" + marker + "\\n' > /dev/kmsg"
        r = call(["shell", command])
        if r.returncode:
            raise SystemExit("kmsg marker write failed")
        after = shell("dmesg-after-marker", "dmesg")
        if marker not in after:
            raise SystemExit("Marker was not readable in current dmesg")
        (args.out / "marker.json").write_text(json.dumps({
            "boot_id": boot_id, "marker": marker, "kernel": kernel.strip(),
        }, indent=2) + "\n", encoding="utf-8")
    result = {"checks": checks, "retention": retention,
              "baseline_only": not args.expect_v2,
              "early_start_passed": all(v is True for v in checks.values()),
              "pstore_pull_succeeded": pull.returncode == 0,
              "no_reboot_performed": True}
    (args.out / "validation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if args.expect_v2 and (not result["early_start_passed"] or
                           (args.previous_marker and retention["status"] != "pass")):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
