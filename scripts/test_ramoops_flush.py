#!/usr/bin/env python3
"""Compile the exact flush helper with stubs; not a hardware retention test."""
from pathlib import Path
import subprocess
import tempfile

STUB = r'''
#include <assert.h>
#include <stddef.h>
#define notrace
struct persistent_ram_zone { void *vaddr; size_t size; };
struct ramoops_context {
    unsigned long memtype, size, record_size, console_size, pmsg_size, ftrace_size;
    struct persistent_ram_zone *cprz, *mprz;
};
static unsigned int calls;
static unsigned long starts[3], ends[3];
static void dcache_clean_poc(unsigned long start, unsigned long end) {
    assert(calls < 3); starts[calls] = start; ends[calls++] = end;
}
'''
TEST = r'''
int main(void) {
    struct persistent_ram_zone dump = {(void *)0x1000UL, 0x40000};
    struct persistent_ram_zone console = {(void *)0x41000UL, 0x100000};
    struct persistent_ram_zone pmsg = {(void *)0x141000UL, 0x100000};
    struct ramoops_context c = {2, 0x240000, 0x40000, 0x100000, 0x100000, 0, &console, &pmsg};
    c17_ramoops_flush_dump(&c, &dump);
    assert(calls == 3 && starts[0] == 0x1000 && ends[0] == 0x41000);
    assert(starts[1] == 0x41000 && ends[1] == 0x141000);
    assert(starts[2] == 0x141000 && ends[2] == 0x241000);
    calls = 0; c.memtype = 0; c17_ramoops_flush_dump(&c, &dump); assert(!calls);
    c.memtype = 2; c.size = 0x400000; c17_ramoops_flush_dump(&c, &dump); assert(!calls);
    c.size = 0x240000; c.record_size = 0; c17_ramoops_flush_dump(&c, &dump); assert(!calls);
    c.record_size = 0x40000; c.console_size = 0x40000; c17_ramoops_flush_dump(&c, &dump); assert(!calls);
    c.console_size = 0x100000; c.pmsg_size = 0; c17_ramoops_flush_dump(&c, &dump); assert(!calls);
    c.pmsg_size = 0x100000; c.ftrace_size = 1; c17_ramoops_flush_dump(&c, &dump); assert(!calls);
    c17_ramoops_flush_zone(NULL); assert(!calls);
    dump.vaddr = NULL; c17_ramoops_flush_zone(&dump); assert(!calls);
    dump.vaddr = (void *)0x1000UL; dump.size = 0; c17_ramoops_flush_zone(&dump); assert(!calls);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='c17-flush-test-') as temp:
    root = Path(temp)
    source = root / 'test.c'
    source.write_text(STUB + (Path(__file__).parent / 'c17-bootlog/ramoops-flush.c').read_text() + TEST)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(root / 'test')], check=True)
    subprocess.run([str(root / 'test')], check=True)
print('PASS: exact flush ranges, null/zero guards, six layout gates; hardware retention not tested')
