// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Intel Corporation.
 *
 * Authors:
 * Ramalingam C <ramalingam.c@intel.com>
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/firmware.h>

#include <drm/drm_hdcp.h>
#include <drm/drm_sysfs.h>
#include <drm/drm_print.h>
#include <drm/drm_device.h>
#include <drm/drm_property.h>
#include <drm/drm_mode_object.h>
#include <drm/drm_connector.h>

struct hdcp_srm {
	u8 *srm_buf;
	size_t received_srm_sz;
	u32 revocated_ksv_cnt;
	u8 *revocated_ksv_list;

	/* Mutex to protect above struct member */
	struct mutex mutex;
} *srm_data;

static inline void drm_hdcp_print_ksv(const char *ksv)
{
	DRM_DEBUG("\t%#04x, %#04x, %#04x, %#04x, %#04x\n", *ksv & 0xff,
		  *(ksv + 1) & 0xff, *(ksv + 2) & 0xff, *(ksv + 3) & 0xff,
		  *(ksv + 4) & 0xff);
}

static u32 drm_hdcp_get_revocated_ksv_count(const char *buf, u32 vrls_length)
{
	u32 parsed_bytes = 0, ksv_count = 0, vrl_ksv_cnt, vrl_sz;

	do {
		vrl_ksv_cnt = *buf;
		ksv_count += vrl_ksv_cnt;

		vrl_sz = (vrl_ksv_cnt * DRM_HDCP_KSV_LEN) + 1;
		buf += vrl_sz;
		parsed_bytes += vrl_sz;
	} while (parsed_bytes < vrls_length);

	return ksv_count;
}

static u32 drm_hdcp_get_revocated_ksvs(const char *buf, u8 *revocated_ksv_list,
				       u32 vrls_length)
{
	u32 parsed_bytes = 0, ksv_count = 0;
	u32 vrl_ksv_cnt, vrl_ksv_sz, vrl_idx = 0;

	do {
		vrl_ksv_cnt = *buf;
		vrl_ksv_sz = vrl_ksv_cnt * DRM_HDCP_KSV_LEN;

		buf++;

		DRM_DEBUG("vrl: %d, Revoked KSVs: %d\n", vrl_idx++,
			  vrl_ksv_cnt);
		memcpy(revocated_ksv_list, buf, vrl_ksv_sz);

		ksv_count += vrl_ksv_cnt;
		revocated_ksv_list += vrl_ksv_sz;
		buf += vrl_ksv_sz;

		parsed_bytes += (vrl_ksv_sz + 1);
	} while (parsed_bytes < vrls_length);

	return ksv_count;
}

static int drm_hdcp_parse_hdcp1_srm(const char *buf, size_t count)
{
	struct hdcp_srm_header *header;
	u32 vrl_length, ksv_count;

	if (count < (sizeof(struct hdcp_srm_header) +
	    DRM_HDCP_1_4_VRL_LENGTH_SIZE + DRM_HDCP_1_4_DCP_SIG_SIZE)) {
		DRM_ERROR("Invalid blob length\n");
		return -EINVAL;
	}

	header = (struct hdcp_srm_header *)buf;
	mutex_lock(&srm_data->mutex);
	DRM_DEBUG("SRM ID: 0x%x, SRM Ver: 0x%x, SRM Gen No: 0x%x\n",
		  header->spec_indicator.srm_id,
		  __swab16(header->srm_version), header->srm_gen_no);

	WARN_ON(header->spec_indicator.reserved_hi ||
		header->spec_indicator.reserved_lo);

	if (header->spec_indicator.srm_id != DRM_HDCP_1_4_SRM_ID) {
		DRM_ERROR("Invalid srm_id\n");
		mutex_unlock(&srm_data->mutex);
		return -EINVAL;
	}

	buf = buf + sizeof(*header);
	vrl_length = (*buf << 16 | *(buf + 1) << 8 | *(buf + 2));
	if (count < (sizeof(struct hdcp_srm_header) + vrl_length) ||
	    vrl_length < (DRM_HDCP_1_4_VRL_LENGTH_SIZE +
			  DRM_HDCP_1_4_DCP_SIG_SIZE)) {
		DRM_ERROR("Invalid blob length or vrl length\n");
		mutex_unlock(&srm_data->mutex);
		return -EINVAL;
	}

	/* Length of the all vrls combined */
	vrl_length -= (DRM_HDCP_1_4_VRL_LENGTH_SIZE +
		       DRM_HDCP_1_4_DCP_SIG_SIZE);

	if (!vrl_length) {
		DRM_ERROR("No vrl found\n");
		mutex_unlock(&srm_data->mutex);
		return -EINVAL;
	}

	buf += DRM_HDCP_1_4_VRL_LENGTH_SIZE;
	ksv_count = drm_hdcp_get_revocated_ksv_count(buf, vrl_length);
	if (!ksv_count) {
		DRM_DEBUG("Revocated KSV count is 0\n");
		mutex_unlock(&srm_data->mutex);
		return count;
	}

	kfree(srm_data->revocated_ksv_list);
	srm_data->revocated_ksv_list = kzalloc(ksv_count * DRM_HDCP_KSV_LEN,
					       GFP_KERNEL);
	if (!srm_data->revocated_ksv_list) {
		DRM_ERROR("Out of Memory\n");
		mutex_unlock(&srm_data->mutex);
		return -ENOMEM;
	}

	if (drm_hdcp_get_revocated_ksvs(buf, srm_data->revocated_ksv_list,
					vrl_length) != ksv_count) {
		srm_data->revocated_ksv_cnt = 0;
		kfree(srm_data->revocated_ksv_list);
		mutex_unlock(&srm_data->mutex);
		return -EINVAL;
	}

	srm_data->revocated_ksv_cnt = ksv_count;
	mutex_unlock(&srm_data->mutex);
	return count;
}

static int drm_hdcp_parse_hdcp2_srm(const char *buf, size_t count)
{
	struct hdcp2_srm_header *header;
	u32 vrl_length, ksv_count, ksv_sz;

	mutex_lock(&srm_data->mutex);
	if (count < (sizeof(struct hdcp2_srm_header) +
	    DRM_HDCP_2_VRL_LENGTH_SIZE + DRM_HDCP_2_DCP_SIG_SIZE)) {
		DRM_ERROR("Invalid blob length\n");
		mutex_unlock(&srm_data->mutex);
		return -EINVAL;
	}

	header = (struct hdcp2_srm_header *)buf;
	DRM_DEBUG("SRM ID: 0x%x, SRM Ver: 0x%x, SRM Gen No: 0x%x\n",
		  header->spec_indicator.srm_id,
		  __swab16(header->srm_version), header->srm_gen_no);

	if (header->spec_indicator.reserved)
		return -EINVAL;

	buf = buf + sizeof(*header);
	vrl_length = (*buf << 16 | *(buf + 1) << 8 | *(buf + 2));

	if (count < (sizeof(struct hdcp2_srm_header) + vrl_length) ||
	    vrl_length < (DRM_HDCP_2_VRL_LENGTH_SIZE +
	    DRM_HDCP_2_DCP_SIG_SIZE)) {
		DRM_ERROR("Invalid blob length or vrl length\n");
		mutex_unlock(&srm_data->mutex);
		return -EINVAL;
	}

	/* Length of the all vrls combined */
	vrl_length -= (DRM_HDCP_2_VRL_LENGTH_SIZE +
		       DRM_HDCP_2_DCP_SIG_SIZE);

	if (!vrl_length) {
		DRM_ERROR("No vrl found\n");
		mutex_unlock(&srm_data->mutex);
		return -EINVAL;
	}

	buf += DRM_HDCP_2_VRL_LENGTH_SIZE;
	ksv_count = (*buf << 2) | DRM_HDCP_2_KSV_COUNT_2_LSBITS(*(buf + 1));
	if (!ksv_count) {
		DRM_DEBUG("Revocated KSV count is 0\n");
		mutex_unlock(&srm_data->mutex);
		return count;
	}

	kfree(srm_data->revocated_ksv_list);
	srm_data->revocated_ksv_list = kzalloc(ksv_count * DRM_HDCP_KSV_LEN,
					       GFP_KERNEL);
	if (!srm_data->revocated_ksv_list) {
		DRM_ERROR("Out of Memory\n");
		mutex_unlock(&srm_data->mutex);
		return -ENOMEM;
	}

	ksv_sz = ksv_count * DRM_HDCP_KSV_LEN;
	buf += DRM_HDCP_2_NO_OF_DEV_PLUS_RESERVED_SZ;

	DRM_DEBUG("Revoked KSVs: %d\n", ksv_count);
	memcpy(srm_data->revocated_ksv_list, buf, ksv_sz);

	srm_data->revocated_ksv_cnt = ksv_count;
	mutex_unlock(&srm_data->mutex);
	return count;
}

static inline bool is_srm_version_hdcp1(const char *buf)
{
	return ((u8)*buf) == DRM_HDCP_1_4_SRM_ID << 4;
}

static inline bool is_srm_version_hdcp2(const char *buf)
{
	return ((u8)*buf) == (DRM_HDCP_2_SRM_ID << 4 |
			     DRM_HDCP_2_INDICATOR);
}

static ssize_t drm_hdcp_srm_update(const char *buf, size_t count)
{
	if (is_srm_version_hdcp1(buf))
		return (ssize_t)drm_hdcp_parse_hdcp1_srm(buf, count);
	else if (is_srm_version_hdcp2(buf))
		return (ssize_t)drm_hdcp_parse_hdcp2_srm(buf, count);

	return (ssize_t)-EINVAL;
}

void drm_hdcp_request_srm(struct drm_device *drm_dev)
{
	char fw_name[36] = "display_hdcp_srm.bin";
	const struct firmware *fw;

	int ret;

	ret = request_firmware_direct(&fw, (const char *)fw_name,
				      drm_dev->dev);
	if (ret < 0)
		goto exit;

	if (fw->size && fw->data)
		drm_hdcp_srm_update((const char *)fw->data, fw->size);

exit:
	release_firmware(fw);
}

/* Check if any of the KSV is revocated by DCP LLC through SRM table */
bool drm_hdcp_ksvs_revocated(struct drm_device *drm_dev, u8 *ksvs,
			     u32 ksv_count)
{
	u32 rev_ksv_cnt, cnt, i, j;
	u8 *rev_ksv_list;

	if (!srm_data)
		return false;

	drm_hdcp_request_srm(drm_dev);

	mutex_lock(&srm_data->mutex);
	rev_ksv_cnt = srm_data->revocated_ksv_cnt;
	rev_ksv_list = srm_data->revocated_ksv_list;

	/* If the Revocated ksv list is empty */
	if (!rev_ksv_cnt || !rev_ksv_list) {
		mutex_unlock(&srm_data->mutex);
		return false;
	}

	for  (cnt = 0; cnt < ksv_count; cnt++) {
		rev_ksv_list = srm_data->revocated_ksv_list;
		for (i = 0; i < rev_ksv_cnt; i++) {
			for (j = 0; j < DRM_HDCP_KSV_LEN; j++)
				if (*(ksvs + j) != *(rev_ksv_list + j)) {
					break;
				} else if (j == (DRM_HDCP_KSV_LEN - 1)) {
					DRM_DEBUG("Revocated KSV is ");
					drm_hdcp_print_ksv(ksvs);
					mutex_unlock(&srm_data->mutex);
					return true;
				}
			/* Move the offset to next KSV in the revocated list */
			rev_ksv_list += DRM_HDCP_KSV_LEN;
		}

		/* Iterate to next ksv_offset */
		ksvs += DRM_HDCP_KSV_LEN;
	}
	mutex_unlock(&srm_data->mutex);
	return false;
}
EXPORT_SYMBOL_GPL(drm_hdcp_ksvs_revocated);

int drm_setup_hdcp_srm(struct class *drm_class)
{
	srm_data = kzalloc(sizeof(*srm_data), GFP_KERNEL);
	if (!srm_data)
		return -ENOMEM;

	srm_data->srm_buf = kcalloc(DRM_HDCP_SRM_GEN1_MAX_BYTES,
				    sizeof(u8), GFP_KERNEL);
	if (!srm_data->srm_buf) {
		kfree(srm_data);
		return -ENOMEM;
	}
	mutex_init(&srm_data->mutex);

	return 0;
}

void drm_teardown_hdcp_srm(struct class *drm_class)
{
	if (srm_data) {
		kfree(srm_data->srm_buf);
		kfree(srm_data->revocated_ksv_list);
		kfree(srm_data);
	}
}

static struct drm_prop_enum_list drm_cp_enum_list[] = {
	{ DRM_MODE_CONTENT_PROTECTION_UNDESIRED, "Undesired" },
	{ DRM_MODE_CONTENT_PROTECTION_DESIRED, "Desired" },
	{ DRM_MODE_CONTENT_PROTECTION_ENABLED, "Enabled" },
};
DRM_ENUM_NAME_FN(drm_get_content_protection_name, drm_cp_enum_list)

static struct drm_prop_enum_list drm_hdcp_content_type_enum_list[] = {
	{ DRM_MODE_HDCP_CONTENT_TYPE0, "HDCP Type0" },
	{ DRM_MODE_HDCP_CONTENT_TYPE1, "HDCP Type1" },
};
DRM_ENUM_NAME_FN(drm_get_hdcp_content_type_name,
		 drm_hdcp_content_type_enum_list)

/**
 * drm_connector_attach_content_protection_property - attach content protection
 * property
 *
 * @connector: connector to attach CP property on.
 * @hdcp_content_type: is HDCP Content Type property needed for connector
 *
 * This is used to add support for content protection on select connectors.
 * Content Protection is intentionally vague to allow for different underlying
 * technologies, however it is most implemented by HDCP.
 *
 * When hdcp_content_type is true enum property called HDCP Content Type is
 * created (if it is not already) and attached to the connector.
 *
 * This property is used for sending the protected content's stream type
 * from userspace to kernel on selected connectors. Protected content provider
 * will decide their type of their content and declare the same to kernel.
 *
 * Content type will be used during the HDCP 2.2 authentication.
 * Content type will be set to &drm_connector_state.hdcp_content_type.
 *
 * The content protection will be set to &drm_connector_state.content_protection
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
int drm_connector_attach_content_protection_property(
		struct drm_connector *connector, bool hdcp_content_type)
{
	struct drm_device *dev = connector->dev;
	struct drm_property *prop =
			dev->mode_config.content_protection_property;

	if (!prop)
		prop = drm_property_create_enum(dev, 0, "Content Protection",
						drm_cp_enum_list,
						ARRAY_SIZE(drm_cp_enum_list));
	if (!prop)
		return -ENOMEM;

	drm_object_attach_property(&connector->base, prop,
				   DRM_MODE_CONTENT_PROTECTION_UNDESIRED);
	dev->mode_config.content_protection_property = prop;

	if (!hdcp_content_type)
		return 0;

	prop = dev->mode_config.hdcp_content_type_property;
	if (!prop)
		prop = drm_property_create_enum(dev, 0, "HDCP Content Type",
					drm_hdcp_content_type_enum_list,
					ARRAY_SIZE(
					drm_hdcp_content_type_enum_list));
	if (!prop)
		return -ENOMEM;

	drm_object_attach_property(&connector->base, prop,
				   DRM_MODE_HDCP_CONTENT_TYPE0);
	dev->mode_config.hdcp_content_type_property = prop;

	return 0;
}
EXPORT_SYMBOL(drm_connector_attach_content_protection_property);

void drm_hdcp_update_content_protection(struct drm_connector *connector,
					u64 val)
{
	struct drm_device *dev = connector->dev;
	struct drm_connector_state *state = connector->state;

	WARN_ON(!drm_modeset_is_locked(&dev->mode_config.connection_mutex));
	if (state->content_protection == val)
		return;

	state->content_protection = val;
	drm_sysfs_connector_status_event(connector,
				 dev->mode_config.content_protection_property);
}
EXPORT_SYMBOL(drm_hdcp_update_content_protection);
