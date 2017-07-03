/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright © 2017-2018 Intel Corporation
 *
 * Mei_hdcp.c: HDCP client driver for mei bus
 *
 * Authors:
 * Ramalingam C <ramalingam.c@intel.com>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uuid.h>
#include <linux/mei_cl_bus.h>

static int mei_hdcp_probe(struct mei_cl_device *cldev,
			  const struct mei_cl_device_id *id)
{
	int ret;

	ret = mei_cldev_enable(cldev);
	if (ret < 0)
		dev_err(&cldev->dev, "mei_cldev_enable Failed. %d\n", ret);

	return ret;
}

static int mei_hdcp_remove(struct mei_cl_device *cldev)
{
	return mei_cldev_disable(cldev);
}

#define MEI_UUID_HDCP		UUID_LE(0xB638AB7E, 0x94E2, 0x4EA2, 0xA5, \
					0x52, 0xD1, 0xC5, 0x4B, \
					0x62, 0x7F, 0x04)

static struct mei_cl_device_id mei_hdcp_tbl[] = {
	{ .uuid = MEI_UUID_HDCP, .version = MEI_CL_VERSION_ANY },
	{ }
};
MODULE_DEVICE_TABLE(mei, mei_hdcp_tbl);

static struct mei_cl_driver mei_hdcp_driver = {
	.id_table	= mei_hdcp_tbl,
	.name		= KBUILD_MODNAME,
	.probe		= mei_hdcp_probe,
	.remove		= mei_hdcp_remove,
};

module_mei_cl_driver(mei_hdcp_driver);

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("MEI HDCP");
