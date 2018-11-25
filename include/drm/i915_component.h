/*
 * Copyright © 2014 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _I915_COMPONENT_H_
#define _I915_COMPONENT_H_

#include <linux/mutex.h>

#include "drm_audio_component.h"

#include <drm/drm_hdcp.h>

/* MAX_PORT is the number of port
 * It must be sync with I915_MAX_PORTS defined i915_drv.h
 */
#define MAX_PORTS 6

/**
 * struct i915_audio_component - Used for direct communication between i915 and hda drivers
 */
struct i915_audio_component {
	/**
	 * @base: the drm_audio_component base class
	 */
	struct drm_audio_component	base;

	/**
	 * @aud_sample_rate: the array of audio sample rate per port
	 */
	int aud_sample_rate[MAX_PORTS];
};

struct i915_hdcp_component_ops {
	/**
	 * @owner: mei_hdcp module
	 */
	struct module *owner;

	int (*initiate_hdcp2_session)(struct device *dev,
				      void *hdcp_data,
				      struct hdcp2_ake_init *ake_data);
	int (*verify_receiver_cert_prepare_km)(struct device *dev,
					       void *hdcp_data,
					       struct hdcp2_ake_send_cert
								*rx_cert,
					       bool *km_stored,
					       struct hdcp2_ake_no_stored_km
								*ek_pub_km,
					       size_t *msg_sz);
	int (*verify_hprime)(struct device *dev,
			     void *hdcp_data,
			     struct hdcp2_ake_send_hprime *rx_hprime);
	int (*store_pairing_info)(struct device *dev,
				  void *hdcp_data,
				  struct hdcp2_ake_send_pairing_info
								*pairing_info);
	int (*initiate_locality_check)(struct device *dev,
				       void *hdcp_data,
				       struct hdcp2_lc_init *lc_init_data);
	int (*verify_lprime)(struct device *dev,
			     void *hdcp_data,
			     struct hdcp2_lc_send_lprime *rx_lprime);
	int (*get_session_key)(struct device *dev,
			       void *hdcp_data,
			       struct hdcp2_ske_send_eks *ske_data);
	int (*repeater_check_flow_prepare_ack)(struct device *dev,
					       void *hdcp_data,
					       struct hdcp2_rep_send_receiverid_list
								*rep_topology,
					       struct hdcp2_rep_send_ack
								*rep_send_ack);
	int (*verify_mprime)(struct device *dev,
			     void *hdcp_data,
			     struct hdcp2_rep_stream_ready *stream_ready);
	int (*enable_hdcp_authentication)(struct device *dev,
					  void *hdcp_data);
	int (*close_hdcp_session)(struct device *dev,
				  void *hdcp_data);
};

/**
 * struct i915_hdcp_component_master - Used for communication between i915
 * and mei_hdcp for HDCP2.2 services.
 */
struct i915_hdcp_component_master {
	/**
	 * @dev: a device providing hdcp
	 */
	struct device *dev;
	/**
	 * @mutex: Mutex to protect the state of dev
	 */
	struct mutex mutex;
	/**
	 * @ops: Ops implemented by mei_hdcp driver, used by i915 driver.
	 */
	const struct i915_hdcp_component_ops *ops;
};

#endif /* _I915_COMPONENT_H_ */
