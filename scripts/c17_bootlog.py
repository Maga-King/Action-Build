#!/usr/bin/env python3
"""Opt-in, fail-closed diagnostics for the real OnePlus 13 6.6.118 tree."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

REQUIRED = {
    "PRINTK": "y", "PRINTK_TIME": "y", "IKCONFIG": "y", "IKCONFIG_PROC": "y",
    "LOG_BUF_SHIFT": "22", "KALLSYMS": "y", "PSTORE": "y", "PSTORE_RAM": "y",
    "PSTORE_CONSOLE": "y", "PSTORE_PMSG": "y", "PSTORE_DEFAULT_KMSG_BYTES": "262144",
    "SECURITY_SELINUX": "y", "SECURITY_SELINUX_DEVELOP": "y",
    "OF": "y", "OF_RESERVED_MEM": "y",
}

RAM_ANCHOR = "\tif (!pdata->mem_size || (!pdata->record_size && !pdata->console_size &&"
RAM_PATCH = """\t/* C17_BOOTLOG: use only the existing OP13 reserved region. */
\tif (pdata->mem_size == 0x240000 && pdata->console_size == 0x40000 &&
\t    pdata->pmsg_size == 0x200000 && !pdata->record_size &&
\t    !pdata->ftrace_size && !pdata->ecc_info.ecc_size) {
\t\t/* Same base and total size; 256 KiB dump + 1 MiB console + 1 MiB pmsg. */
\t\tpdata->record_size = 0x40000;
\t\tpdata->console_size = 0x100000;
\t\tpdata->pmsg_size = 0x100000;
\t\tpdata->max_reason = KMSG_DUMP_MAX;
\t\tpr_warn("C17_BOOTLOG: existing 0x240000 region repartitioned for reboot/panic logs\\n");
\t} else {
\t\t/* Never guess a physical address or shrink an unfamiliar layout. */
\t\tpr_warn("C17_BOOTLOG: unrecognized ramoops layout, leaving it unchanged\\n");
\t}

"""

def early_ramoops_source(original):
    """Bind the existing qcom DT node before userspace, without duplicate devices."""
    fragment = (Path(__file__).parent / "c17-bootlog/ramoops-qcom-early.c").read_text()
    patched = replace_once(original, "#include <linux/of_address.h>\n",
                           "#include <linux/of_address.h>\n#include <linux/of_reserved_mem.h>\n")
    anchor = "static int ramoops_parse_dt(struct platform_device *pdev,"
    patched = replace_once(patched, anchor, fragment + "\n" + anchor)
    anchor = '\tdev_dbg(&pdev->dev, "using Device Tree\\n");'
    patched = replace_once(patched, anchor,
        '\tif (of_device_is_compatible(of_node, "qcom,ramoops"))\n'
        '\t\treturn ramoops_parse_op13_dt(pdev, pdata);\n\n' + anchor)
    patched = replace_once(patched, '\t{ .compatible = "ramoops" },',
        '\t{ .compatible = "ramoops" },\n\t{ .compatible = "qcom,ramoops" },')
    anchor = '\t/*\n\t * Update the module parameter variables as well so they are visible'
    patched = replace_once(patched, anchor,
        '\tif (of_device_is_compatible(dev_of_node(dev), "qcom,ramoops"))\n'
        '\t\tdev_info(dev, "C17_BOOTLOG_V2: early DT backend ready\\n");\n\n' + anchor)
    return replace_once(patched, RAM_ANCHOR, RAM_PATCH + RAM_ANCHOR)

def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f"Expected one source anchor, got {text.count(old)}: {old[:100]}")
    return text.replace(old, new, 1)

def version(kernel):
    text = (kernel / "Makefile").read_text()
    return ".".join(re.search(rf"^{key}\s*=\s*(\d+)$", text, re.M)[1]
                    for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL"))

def config_values(path):
    return dict(re.findall(r"^CONFIG_([A-Z0-9_]+)=(.*)$", path.read_text(), re.M))

def prepare(kernel, mode, report):
    if version(kernel) != "6.6.118":
        raise RuntimeError("Refusing a kernel other than actual 6.6.118")
    edits = {}
    ram = kernel / "fs/pstore/ram.c"
    original = ram.read_text()
    if "C17_BOOTLOG:" in original:
        raise RuntimeError("Diagnostic patch is already present; use a clean source tree")
    edits[ram] = early_ramoops_source(original)
    if mode == "permissive":
        security = kernel / "security/selinux/include/security.h"
        edits[security] = replace_once(security.read_text(),
            "\tWRITE_ONCE(selinux_state.enforcing, value);",
            "\t/* C17_BOOTLOG: temporary diagnostic kernel, truthfully permissive. */\n"
            "\tWRITE_ONCE(selinux_state.enforcing, false);")
        hooks = kernel / "security/selinux/hooks.c"
        edits[hooks] = replace_once(hooks.read_text(),
            "\tenforcing_set(selinux_enforcing_boot);",
            "\t/* C17_BOOTLOG: keep boot message and effective state consistent. */\n"
            "\tselinux_enforcing_boot = 0;\n\tenforcing_set(selinux_enforcing_boot);")
        fs = kernel / "security/selinux/selinuxfs.c"
        edits[fs] = replace_once(fs.read_text(),
            "\tnew_value = !!scan_value;",
            "\t/* C17_BOOTLOG: init cannot re-enable enforcing in this debug build. */\n"
            "\tif (scan_value)\n"
            "\t\tpr_warn_once(\"C17_BOOTLOG: enforcing request overridden; diagnostic kernel is PERMISSIVE\\n\");\n"
            "\tnew_value = false;")
    cfg = kernel / "arch/arm64/configs/gki_defconfig"
    text = cfg.read_text()
    for key, value in REQUIRED.items():
        pattern = rf"^(?:CONFIG_{key}=.*|# CONFIG_{key} is not set)\n?"
        text = re.sub(pattern, "", text, flags=re.M)
        text = text.rstrip() + f"\nCONFIG_{key}={value}\n"
    edits[cfg] = text
    # Check every anchor before any source mutation. Save exact before/after diff.
    changes = []
    for path, modified in edits.items():
        before = path.read_text()
        rel = path.relative_to(kernel).as_posix()
        changes.extend(difflib.unified_diff(before.splitlines(True), modified.splitlines(True),
                                            fromfile="a/" + rel, tofile="b/" + rel))
        path.write_text(modified, newline="\n")
    (report / "kernel-diagnostic.patch").write_text("".join(changes))
    rev = subprocess.run(["git", "-C", str(kernel), "rev-parse", "HEAD"],
                         capture_output=True, text=True)
    (report / "build-mode.json").write_text(json.dumps({
        "version": version(kernel), "mode": mode, "source_commit": rev.stdout.strip(),
        "requires_runtime_validation": True, "metadata_before_init_guaranteed": False,
        "physical_address_changed": False, "total_reserved_size_changed": False,
        "original_layout": "0x240000 total, 0x40000 console, 0x200000 pmsg, no dmesg",
        "new_layout": "0x40000 dmesg, 0x100000 console, 0x100000 pmsg",
        "cold_boot_retention_guaranteed": False,
        "diagnostic_revision": 2,
        "early_backend": "builtin ramoops binds existing qcom,ramoops DT device",
        "vendor_module_removed": False,
        "ram_source_sha256": hashlib.sha256(edits[ram].encode()).hexdigest(),
    }, indent=2) + "\n")
    print(f"Prepared OP13 {version(kernel)} diagnostic mode={mode}")

def verify(kernel, mode, report):
    config = kernel / "out/.config"
    actual = config_values(config)
    errors = [f"CONFIG_{k}: wanted {v}, got {actual.get(k)}"
              for k, v in REQUIRED.items() if actual.get(k) != v]
    if version(kernel) != "6.6.118":
        errors.append("Kernel version changed after preparation")
    ram_source = (kernel / "fs/pstore/ram.c").read_text()
    evidence = json.loads((report / "build-mode.json").read_text())
    if hashlib.sha256(ram_source.encode()).hexdigest() != evidence.get("ram_source_sha256"):
        errors.append("Ramoops source differs from the prepared and recorded patch")
    for required in ('ramoops_parse_op13_dt', '"qcom,ramoops"',
                     'C17_BOOTLOG_V2: early DT backend ready', 'postcore_initcall(ramoops_init)'):
        if required not in ram_source:
            errors.append(f"Early ramoops source missing: {required}")
    security = (kernel / "security/selinux/include/security.h").read_text()
    if mode == "permissive" and "WRITE_ONCE(selinux_state.enforcing, false);" not in security:
        errors.append("Permissive source patch missing")
    if mode == "enforcing" and "C17_BOOTLOG:" in security:
        errors.append("Unexpected force-permissive patch in enforcing mode")
    shutil.copyfile(config, report / "effective-kernel.config")
    (report / "configuration-validation.json").write_text(json.dumps({
        "passed": not errors, "errors": errors, "mode": mode,
    }, indent=2) + "\n")
    if errors:
        raise RuntimeError("\n".join(errors))
    print("Effective .config and source checks passed; this is not a boot test")

def package(kernel, mode, report):
    verify(kernel, mode, report)
    source = Path(__file__).parent / "c17-bootlog"
    shutil.copyfile(source / "README.txt", report / "README.txt")
    shutil.copyfile(source / "collect.sh", report / "collect.sh")
    shutil.copyfile(Path(__file__).parent / "validate_c17_bootlog_device.py",
                    report / "validate_c17_bootlog_device.py")
    with zipfile.ZipFile(report / "C17-Metadata-Log-Collector-optional.zip", "w",
                         compression=zipfile.ZIP_DEFLATED) as z:
        for name in ("module.prop", "post-fs-data.sh", "collect.sh", "README.txt"):
            entry = zipfile.ZipInfo(name)
            entry.external_attr = (0o100755 if name.endswith(".sh") else 0o100644) << 16
            z.writestr(entry, (source / name).read_bytes())
    image = Path("AnyKernel3/Image")
    if not image.is_file():
        raise RuntimeError("Final AnyKernel3 Image missing")
    (report / "Image.sha256").write_text(hashlib.sha256(image.read_bytes()).hexdigest() + "  Image\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("prepare", "verify", "package"))
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("enforcing", "permissive"))
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    args.report.mkdir(parents=True, exist_ok=True)
    globals()[args.command](args.kernel, args.mode, args.report)

if __name__ == "__main__":
    main()
