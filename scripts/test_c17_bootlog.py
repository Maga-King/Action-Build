#!/usr/bin/env python3
"""Small source-fixture tests; does not download or compile the kernel."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile

spec = importlib.util.spec_from_file_location("bootlog", Path(__file__).with_name("c17_bootlog.py"))
bootlog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootlog)

def fixture(root, reference, kernel=None):
    mapping = {
        "Makefile": "Makefile", "ram.c": "fs/pstore/ram.c",
        "security.h": "security/selinux/include/security.h",
        "hooks.c": "security/selinux/hooks.c", "selinuxfs.c": "security/selinux/selinuxfs.c",
        "gki_defconfig": "arch/arm64/configs/gki_defconfig",
        "reboot.c": "kernel/reboot.c",
    }
    for src, dest in mapping.items():
        p = root / dest
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(kernel / dest if kernel else reference / src, p)

def main():
    p = argparse.ArgumentParser()
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--reference", type=Path)
    source.add_argument("--kernel", type=Path)
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="c17-bootlog-test-") as temp:
        for mode in ("enforcing",):
            root = Path(temp) / mode
            fixture(root, args.reference, args.kernel)
            before = bootlog.selinux_hashes(root)
            report = root / "report"
            report.mkdir()
            bootlog.prepare(root, mode, report)
            assert bootlog.config_values(root / "arch/arm64/configs/gki_defconfig").items() >= bootlog.REQUIRED.items()
            assert (root / "fs/pstore/ram.c").read_text().count("existing OP13 reserved region") == 1
            ram = (root / "fs/pstore/ram.c").read_text()
            assert ram.count('static int ramoops_parse_op13_dt(') == 1
            assert ram.count('{ .compatible = "qcom,ramoops" },') == 1
            assert ram.count('postcore_initcall(ramoops_init);') == 1
            assert ram.index('err = pstore_register(') < ram.index('C17_BOOTLOG_V3: early DT backend ready')
            assert ram.count('platform_device_register_data(') == 1  # Original dummy only.
            assert 'rmem->base' in ram and '0x880000000' not in ram
            assert before == bootlog.selinux_hashes(root)
            reboot = (root / "kernel/reboot.c").read_text().split('void kernel_restart(char *cmd)', 1)[1]
            assert reboot.index('kmsg_dump(KMSG_DUMP_SHUTDOWN);') < reboot.index('kernel_restart_prepare(cmd);')
            assert reboot.index('kernel_restart_prepare(cmd);') < reboot.index('machine_restart(cmd);')
            (root / "out").mkdir()
            shutil.copyfile(root / "arch/arm64/configs/gki_defconfig", root / "out/.config")
            bootlog.verify(root, mode, report)
            security = root / 'security/selinux/include/security.h'
            original_security = security.read_bytes()
            security.write_bytes(original_security + b'\n/* unexpected edit */\n')
            try:
                bootlog.verify(root, mode, report)
            except RuntimeError:
                pass
            else:
                raise AssertionError('SELinux source modification accepted')
            security.write_bytes(original_security)
            original_ram = (root / "fs/pstore/ram.c").read_text()
            (root / "fs/pstore/ram.c").write_text(original_ram.replace('"qcom,ramoops"', '"not-qcom,ramoops"'))
            try:
                bootlog.verify(root, mode, report)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Altered early adapter accepted")
            (root / "fs/pstore/ram.c").write_text(original_ram)
            try:
                bootlog.prepare(root, mode, report)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Reapplication was not refused")
            # Negative test: the effective build config must not silently lose logging.
            config = root / "out/.config"
            config.write_text(config.read_text().replace("CONFIG_PSTORE_RAM=y", "# CONFIG_PSTORE_RAM is not set"))
            try:
                bootlog.verify(root, mode, report)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Invalid effective config accepted")
            assert not json.loads((report / "configuration-validation.json").read_text())["passed"]
        bad = Path(temp) / "wrong-version"
        fixture(bad, args.reference, args.kernel)
        mf = bad / "Makefile"
        mf.write_text(mf.read_text().replace("SUBLEVEL = 118", "SUBLEVEL = 119"))
        report = bad / "report"
        report.mkdir()
        try:
            bootlog.prepare(bad, "enforcing", report)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Wrong version accepted")
        denied = Path(temp) / 'permissive-denied'
        fixture(denied, args.reference, args.kernel)
        untouched = (denied / 'fs/pstore/ram.c').read_bytes()
        try:
            bootlog.prepare(denied, 'permissive', Path(temp))
        except RuntimeError:
            pass
        else:
            raise AssertionError('Permissive accepted')
        assert (denied / 'fs/pstore/ram.c').read_bytes() == untouched
    print("PASS: source anchors, SELinux unchanged/tamper guard, permissive rejected, reboot ordering, reapply/config/version guards")

if __name__ == "__main__":
    main()
