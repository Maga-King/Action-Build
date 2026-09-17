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

def fixture(root, reference):
    mapping = {
        "Makefile": "Makefile", "ram.c": "fs/pstore/ram.c",
        "security.h": "security/selinux/include/security.h",
        "hooks.c": "security/selinux/hooks.c", "selinuxfs.c": "security/selinux/selinuxfs.c",
        "gki_defconfig": "arch/arm64/configs/gki_defconfig",
    }
    for src, dest in mapping.items():
        p = root / dest
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(reference / src, p)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--reference", required=True, type=Path)
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="c17-bootlog-test-") as temp:
        for mode in ("enforcing", "permissive"):
            root = Path(temp) / mode
            fixture(root, args.reference)
            report = root / "report"
            report.mkdir()
            bootlog.prepare(root, mode, report)
            assert bootlog.config_values(root / "arch/arm64/configs/gki_defconfig").items() >= bootlog.REQUIRED.items()
            assert (root / "fs/pstore/ram.c").read_text().count("existing OP13 reserved region") == 1
            ram = (root / "fs/pstore/ram.c").read_text()
            assert ram.count('static int ramoops_parse_op13_dt(') == 1
            assert ram.count('{ .compatible = "qcom,ramoops" },') == 1
            assert ram.count('postcore_initcall(ramoops_init);') == 1
            assert ram.index('err = pstore_register(') < ram.index('C17_BOOTLOG_V2: early DT backend ready')
            assert ram.count('platform_device_register_data(') == 1  # Original dummy only.
            assert 'rmem->base' in ram and '0x880000000' not in ram
            if mode == "enforcing":
                assert (root / "security/selinux/selinuxfs.c").read_bytes() == (args.reference / "selinuxfs.c").read_bytes()
                assert (root / "security/selinux/include/security.h").read_bytes() == (args.reference / "security.h").read_bytes()
            else:
                assert "new_value = false;" in (root / "security/selinux/selinuxfs.c").read_text()
            (root / "out").mkdir()
            shutil.copyfile(root / "arch/arm64/configs/gki_defconfig", root / "out/.config")
            bootlog.verify(root, mode, report)
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
        fixture(bad, args.reference)
        mf = bad / "Makefile"
        mf.write_text(mf.read_text().replace("SUBLEVEL = 118", "SUBLEVEL = 119"))
        report = bad / "report"
        report.mkdir()
        try:
            bootlog.prepare(bad, "permissive", report)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Wrong version accepted")
    print("PASS: actual-source anchors, both modes, no SELinux edit in enforcing mode, reapply guard, effective-config guard, version guard")

if __name__ == "__main__":
    main()
