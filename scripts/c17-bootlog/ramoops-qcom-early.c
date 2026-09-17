/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * C17_BOOTLOG_V2: diagnostic-only adapter for the measured OP13 DT layout.
 * The memory-region lookup follows Qualcomm's qcom_dynamic_ramoops.c.
 * Insert after ramoops_parse_dt_u32() in fs/pstore/ram.c, not a separate module.
 * Binding the existing DT device prevents the later vendor driver from probing
 * that same device. No second platform device or physical reservation is made.
 */
static int ramoops_parse_op13_dt(struct platform_device *pdev,
			       struct ramoops_platform_data *pdata)
{
	struct device_node *np = pdev->dev.of_node;
	struct device_node *region;
	struct reserved_mem *rmem;
	u32 value;
	int ret;

	if (!of_machine_is_compatible("qcom,sun") ||
	    !of_node_name_eq(np, "qcom_ramoops"))
		return -ENODEV;

	region = of_parse_phandle(np, "memory-region", 0);
	if (!region)
		return -ENODEV;
	if (!of_node_name_eq(region, "ramoops-region")) {
		of_node_put(region);
		return -ENODEV;
	}
	rmem = of_reserved_mem_lookup(region);
	of_node_put(region);
	if (!rmem || !rmem->base || rmem->size != 0x240000 ||
	    !IS_ALIGNED(rmem->base, PAGE_SIZE)) {
		dev_warn(&pdev->dev, "C17_BOOTLOG_V2: unknown reservation; vendor fallback retained\n");
		return -ENODEV;
	}

	pdata->mem_address = rmem->base;
	pdata->mem_size = rmem->size;
	pdata->mem_type = 2; /* Match the existing Qualcomm cached mapping. */
	pdata->max_reason = KMSG_DUMP_PANIC;

#define op13_parse_u32(name, field, default_value) do { \
	ret = ramoops_parse_dt_u32(pdev, name, default_value, &value); \
	if (ret < 0) \
		return ret; \
	field = value; \
} while (0)
	op13_parse_u32("mem-type", pdata->mem_type, pdata->mem_type);
	op13_parse_u32("record-size", pdata->record_size, 0);
	op13_parse_u32("console-size", pdata->console_size, 0);
	op13_parse_u32("ftrace-size", pdata->ftrace_size, 0);
	op13_parse_u32("pmsg-size", pdata->pmsg_size, 0);
	op13_parse_u32("ecc-size", pdata->ecc_info.ecc_size, 0);
	op13_parse_u32("flags", pdata->flags, 0);
	op13_parse_u32("max-reason", pdata->max_reason, pdata->max_reason);
#undef op13_parse_u32

	if (pdata->console_size != 0x40000 || pdata->pmsg_size != 0x200000 ||
	    pdata->record_size || pdata->ftrace_size || pdata->ecc_info.ecc_size ||
	    pdata->flags || pdata->mem_type != 2) {
		dev_warn(&pdev->dev, "C17_BOOTLOG_V2: unknown layout; vendor fallback retained\n");
		return -ENODEV;
	}
	return 0;
}

