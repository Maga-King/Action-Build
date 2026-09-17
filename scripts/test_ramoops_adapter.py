#!/usr/bin/env python3
"""Compile the exact adapter against DT stubs; exercise guarded failure paths.

This does not replace compilation against kernel headers or a real boot test.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).parent
STUBS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
#define PAGE_SIZE 4096
#define IS_ALIGNED(x, y) (((x) & ((y) - 1)) == 0)
#define KMSG_DUMP_PANIC 1
#define dev_warn(...) ((void)0)
struct device_node { const char *name; };
struct device { struct device_node *of_node; };
struct platform_device { struct device dev; };
struct reserved_mem { uint64_t base, size; };
struct ramoops_platform_data {
    uint64_t mem_address, mem_size;
    u32 mem_type, max_reason, record_size, console_size, ftrace_size, pmsg_size, flags;
    struct { u32 ecc_size; } ecc_info;
};
static struct device_node device_node = {"qcom_ramoops"}, region_node = {"ramoops-region"};
static struct reserved_mem reservation;
static int has_region, has_reservation, machine_match, refs;
static const char *bad_property;
static u32 console_size, pmsg_size, record_size, mem_type, flags;
static bool of_machine_is_compatible(const char *s) { return machine_match && !strcmp(s, "qcom,sun"); }
static bool of_node_name_eq(struct device_node *n, const char *s) { return n && !strcmp(n->name, s); }
static struct device_node *of_parse_phandle(struct device_node *n, const char *p, int i) {
    (void)n; assert(!strcmp(p, "memory-region")); assert(i == 0);
    if (!has_region) return NULL;
    refs++; return &region_node;
}
static void of_node_put(struct device_node *n) { if (n) refs--; }
static struct reserved_mem *of_reserved_mem_lookup(struct device_node *n) {
    assert(n == &region_node); return has_reservation ? &reservation : NULL;
}
static int ramoops_parse_dt_u32(struct platform_device *p, const char *name, u32 def, u32 *v) {
    (void)p;
    if (bad_property && !strcmp(name, bad_property)) return -EOVERFLOW;
    *v = def;
    if (!strcmp(name, "console-size")) *v = console_size;
    if (!strcmp(name, "pmsg-size")) *v = pmsg_size;
    if (!strcmp(name, "record-size")) *v = record_size;
    if (!strcmp(name, "mem-type")) *v = mem_type;
    if (!strcmp(name, "flags")) *v = flags;
    return 0;
}
'''
TESTS = r'''
static void reset(void) {
    has_region = has_reservation = machine_match = 1; refs = 0;
    device_node.name = "qcom_ramoops"; region_node.name = "ramoops-region";
    reservation.base = 0x880000000ULL; reservation.size = 0x240000;
    console_size = 0x40000; pmsg_size = 0x200000; record_size = 0; mem_type = 2; flags = 0;
    bad_property = NULL;
}
static void check(int expected) {
    struct platform_device dev = {{&device_node}};
    struct ramoops_platform_data data = {0};
    int ret = ramoops_parse_op13_dt(&dev, &data);
    assert(ret == expected); assert(refs == 0);
    if (!ret) {
        assert(data.mem_address == reservation.base);
        assert(data.mem_size == reservation.size);
        assert(data.mem_type == 2);
        assert(data.console_size == console_size && data.pmsg_size == pmsg_size);
    }
}
int main(void) {
    reset(); check(0);
    reset(); reservation.base = 0x900000000ULL; check(0); /* No hard-coded address. */
    reset(); machine_match = 0; check(-ENODEV);
    reset(); device_node.name = "other"; check(-ENODEV);
    reset(); has_region = 0; check(-ENODEV);
    reset(); region_node.name = "other"; check(-ENODEV);
    reset(); has_reservation = 0; check(-ENODEV);
    reset(); reservation.base = 0; check(-ENODEV);
    reset(); reservation.base++; check(-ENODEV);
    reset(); reservation.size++; check(-ENODEV);
    reset(); console_size++; check(-ENODEV);
    reset(); pmsg_size++; check(-ENODEV);
    reset(); record_size = 0x40000; check(-ENODEV);
    reset(); mem_type = 0; check(-ENODEV);
    reset(); flags = 1; check(-ENODEV);
    reset(); bad_property = "console-size"; check(-EOVERFLOW);
    puts("PASS: compiled adapter, 16 DT/layout cases, phandle references balanced");
    return 0;
}
'''


def main():
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        raise SystemExit("A C compiler is required (run in WSL or GitHub Actions)")
    with tempfile.TemporaryDirectory(prefix="c17-adapter-") as temp:
        source = Path(temp) / "test.c"
        exe = Path(temp) / "test"
        source.write_text(STUBS + (ROOT / "c17-bootlog/ramoops-qcom-early.c").read_text() + TESTS)
        subprocess.run([cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    import validate_c17_bootlog_device as device
    expected = {"mem_size": 0x240000, "record_size": 0x40000,
                "console_size": 0x100000, "pmsg_size": 0x100000,
                "ftrace_size": 0, "max_reason": 5}
    assert device.parse_parameters("mem_size=2359296\r\nrecord_size=262144\n") == {
        "mem_size": 0x240000, "record_size": 0x40000}
    early = "[ 0.15] C17_BOOTLOG_V2: early DT backend ready\n[ 0.70] Run /init as init process"
    assert all(v is True for v in device.assess("C17LOG2", expected, "/sys/bus/platform/drivers/ramoops", early).values())
    assert device.assess("C17LOG2", expected, "", "")["ready_before_userspace_init"] is None
    late = early.replace("0.15", "2.15")
    assert device.assess("C17LOG2", expected, "", late)["ready_before_userspace_init"] is False
    v3 = early.replace('C17_BOOTLOG_V2', 'C17_BOOTLOG_V3')
    params3 = dict(expected, mem_type=2)
    assert all(v is True for v in device.assess('C17LOG3', params3, '/sys/bus/platform/drivers/ramoops', v3, 3).values())
    assert not device.assess('C17LOG2', params3, '', v3, 3)['diagnostic_kernel']
    assert not device.assess('C17LOG3', expected, '', v3, 3)['cached_mapping_reported']
    assert device.assess('C17LOG3', params3, '', early, 3)['ready_before_userspace_init'] is None
    print("PASS: CRLF parsing and early/late/missing evidence checks")


if __name__ == "__main__":
    main()
