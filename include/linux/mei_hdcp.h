/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright © 2017-2018 Intel Corporation
 *
 * Authors:
 * Ramalingam C <ramalingam.c@intel.com>
 */

#ifndef _LINUX_MEI_HDCP_H
#define _LINUX_MEI_HDCP_H

/**
 * enum mei_hdcp_ddi - The physical digital display interface (DDI)
 *     available on the platform
 * @MEI_DDI_INVALID_PORT: Not a valid port
 * @MEI_DDI_RANGE_BEGIN: Beginning of the valid DDI port range
 * @MEI_DDI_B: Port DDI B
 * @MEI_DDI_C: Port DDI C
 * @MEI_DDI_D: Port DDI D
 * @MEI_DDI_E: Port DDI E
 * @MEI_DDI_F: Port DDI F
 * @MEI_DDI_A: Port DDI A
 * @MEI_DDI_RANGE_END: End of the valid DDI port range
 */
enum mei_hdcp_ddi {
	MEI_DDI_INVALID_PORT = 0x00,

	MEI_DDI_RANGE_BEGIN = 0x01,
	MEI_DDI_B           = 0x01,
	MEI_DDI_C           = 0x02,
	MEI_DDI_D           = 0x03,
	MEI_DDI_E           = 0x04,
	MEI_DDI_F           = 0x05,
	MEI_DDI_A           = 0x07,
	MEI_DDI_RANGE_END   = MEI_DDI_A,
};

/**
 * enum mei_hdcp_port_type - The types of HDCP 2.2 ports supported
 *
 * @MEI_HDCP_PORT_TYPE_INVALID: Invalid port
 * @MEI_HDCP_PORT_TYPE_INTEGRATED: ports that are integrated into Intel HW
 * @MEI_HDCP_PORT_TYPE_LSPCON: discrete wired Tx port with LSPCON (HDMI 2.0)
 * @MEI_HDCP_PORT_TYPE_CPDP: discrete wired Tx port using the CPDP (DP 1.3)
 */
enum mei_hdcp_port_type {
	MEI_HDCP_PORT_TYPE_INVALID    = 0x00,
	MEI_HDCP_PORT_TYPE_INTEGRATED = 0x01,
	MEI_HDCP_PORT_TYPE_LSPCON     = 0x02,
	MEI_HDCP_PORT_TYPE_CPDP       = 0x03,
};

/*
 * enum mei_hdcp_wired_protocol - Supported integrated wired HDCP protocol.
 * @HDCP_PROTOCOL_INVALID: invalid type
 * @HDCP_PROTOCOL_HDMI: HDMI
 * @HDCP_PROTOCOL_DP: DP
 *
 * Based on this value, Minor difference needed between wired specifications
 * are handled.
 */
enum mei_hdcp_wired_protocol {
	MEI_HDCP_PROTOCOL_INVALID,
	MEI_HDCP_PROTOCOL_HDMI,
	MEI_HDCP_PROTOCOL_DP
};

/**
 * struct mei_hdcp_data - Input data to the mei_hdcp APIs
 * @port: The physical port (ddi).
 * @port_type: The port type.
 * @protocol: The Protocol on the port.
 * @k: Number of streams transmitted on the port.
 *     In case of HDMI & DP SST, a single stream will be
 *     transmitted on the port.
 * @seq_num_m: A sequence number of RepeaterAuth_Stream_Manage msg propagated.
 *     Initialized to 0 on AKE_INIT. Incremented after every successful
 *     transmission of RepeaterAuth_Stream_Manage message. When it rolls
 *     over re-Auth has to be triggered.
 * @streams: array[k] of streamid
 */
struct mei_hdcp_data {
	enum mei_hdcp_ddi port;
	enum mei_hdcp_port_type port_type;
	enum mei_hdcp_wired_protocol protocol;
	u16 k;
	u32 seq_num_m;
	struct hdcp2_streamid_type *streams;
};

#endif /* !_LINUX_MEI_HDCP_H */
