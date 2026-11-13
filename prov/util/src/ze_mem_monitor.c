/*
 * (C) Copyright 2021 Intel Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "ofi_mr.h"

#if HAVE_ZE

#include "ofi_hmem.h"

/* Invoked by the driver on the thread freeing the allocation, before the
 * memory is released, so its range can still be queried. The callback cannot
 * be unregistered, so do nothing once the monitor has stopped.
 */
static void ze_mm_free_cb(void *base)
{
	void *addr;
	size_t size;

	if (ze_monitor->state != FI_MM_STATE_RUNNING)
		return;

	if (ze_hmem_get_base_addr(base, 0, &addr, &size))
		return;

	pthread_rwlock_rdlock(&mm_list_rwlock);
	pthread_mutex_lock(&mm_lock);
	ofi_monitor_notify(ze_monitor, addr, size);
	pthread_mutex_unlock(&mm_lock);
	pthread_rwlock_unlock(&mm_list_rwlock);
}

/* A callback is registered per subscription. The driver keeps one callback
 * per allocation, so the latest registration is the one that fires; a single
 * notification covers every cached MR within the allocation. Registration
 * failure falls back to the allocation id check in ze_mm_valid().
 */
static int ze_mm_subscribe(struct ofi_mem_monitor *monitor, const void *addr,
			   size_t len, union ofi_mr_hmem_info *hmem_info)
{
	void *base;
	size_t size;
	int ret;

	ret = ze_hmem_get_id(addr, &hmem_info->ze_id);
	if (ret || !ze_hmem_free_cb_supported())
		return ret;

	if (!ze_hmem_get_base_addr(addr, len, &base, &size))
		ze_hmem_register_free_cb(base, ze_mm_free_cb, base);

	return FI_SUCCESS;
}

static void ze_mm_unsubscribe(struct ofi_mem_monitor *monitor,
			      const void *addr, size_t len,
			      union ofi_mr_hmem_info *hmem_info)
{
	/* no-op */
}

static bool ze_mm_valid(struct ofi_mem_monitor *monitor,
			const struct ofi_mr_info *info,
			struct ofi_mr_entry *entry)
{
	uint64_t id;
	int ret;

	ret = ze_hmem_get_id(entry->info.iov.iov_base, &id);
	if (ret)
		return false;


	return id == entry->hmem_info.ze_id;
}

static int ze_monitor_start(struct ofi_mem_monitor *monitor)
{
	/* no-op */
	return FI_SUCCESS;
}

#else

static int ze_mm_subscribe(struct ofi_mem_monitor *monitor, const void *addr,
			   size_t len, union ofi_mr_hmem_info *hmem_info)
{
	return -FI_ENOSYS;
}

static void ze_mm_unsubscribe(struct ofi_mem_monitor *monitor,
			      const void *addr, size_t len,
			      union ofi_mr_hmem_info *hmem_info)
{
}

static bool ze_mm_valid(struct ofi_mem_monitor *monitor,
			const struct ofi_mr_info *info,
			struct ofi_mr_entry *entry)
{
	return false;
}

static int ze_monitor_start(struct ofi_mem_monitor *monitor)
{
	return -FI_ENOSYS;
}

#endif /* HAVE_ZE */

void ze_monitor_stop(struct ofi_mem_monitor *monitor)
{
	/* no-op */
}

static struct ofi_mem_monitor ze_mm = {
	.iface = FI_HMEM_ZE,
	.init = ofi_monitor_init,
	.cleanup = ofi_monitor_cleanup,
	.start = ze_monitor_start,
	.stop = ze_monitor_stop,
	.subscribe = ze_mm_subscribe,
	.unsubscribe = ze_mm_unsubscribe,
	.valid = ze_mm_valid,
	.name = "ze",
};

struct ofi_mem_monitor *ze_monitor = &ze_mm;
