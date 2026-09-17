/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * C17_BOOTLOG_V3: the measured OP13 ramoops reservation is cacheable.
 * Clean its existing mappings to PoC at dump time, before the reset path.
 * No remapping, allocation, file I/O, notifier recursion, or raw disk writes.
 * This cannot preserve RAM across power loss or bootloader memory clearing.
 */
static void notrace c17_ramoops_flush_zone(struct persistent_ram_zone *prz)
{
	if (prz && prz->vaddr && prz->size)
		dcache_clean_poc((unsigned long)prz->vaddr,
				 (unsigned long)prz->vaddr + prz->size);
}

static void notrace c17_ramoops_flush_dump(struct ramoops_context *cxt,
					struct persistent_ram_zone *dump)
{
	/* Fail closed for anything outside the diagnostic OP13 layout. */
	if (cxt->memtype != 2 || cxt->size != 0x240000 ||
	    cxt->record_size != 0x40000 || cxt->console_size != 0x100000 ||
	    cxt->pmsg_size != 0x100000 || cxt->ftrace_size)
		return;
	c17_ramoops_flush_zone(dump);
	c17_ramoops_flush_zone(cxt->cprz);
	c17_ramoops_flush_zone(cxt->mprz);
}
