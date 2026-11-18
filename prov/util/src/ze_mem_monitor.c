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

#include "ofi_tree.h"
#include "ofi_iov.h"
#include "ofi_hmem.h"

/* One entry per ZE allocation holding cached MRs. The driver free callback
 * carries only its user data and cannot be unregistered, so the user data is
 * the allocation base address, never an entry pointer. A callback that finds
 * no entry (monitor stopped, entry already detached) is ignored.
 *
 * The driver keeps one callback per allocation and the latest registration
 * wins, so another library registering on the same allocation displaces ours
 * and the entry outlives the allocation. The allocation id detects such a
 * stale entry when the address range is subscribed again.
 */
struct ze_mm_entry {
	struct iovec iov;
	uint64_t id;
	struct ofi_rbnode *node;
	struct dlist_entry entry;
	bool registering;
	bool invalidated;
};

struct ze_mm {
	struct ofi_mem_monitor mm;
	/* NULL until started, and always NULL without driver callback support,
	 * in which case entries are validated by allocation id instead.
	 */
	struct ofi_rbmap *tree;
	/* Only tree access nests under mm_lock; no ZE calls or allocation. */
	pthread_mutex_t lock;
	/* Serializes subscriptions and teardown outside mm_lock. */
	pthread_mutex_t registration_lock;
};

static int ze_mm_start(struct ofi_mem_monitor *monitor);
static void ze_mm_stop(struct ofi_mem_monitor *monitor);
static void ze_mm_init(struct ofi_mem_monitor *monitor);
static void ze_mm_cleanup(struct ofi_mem_monitor *monitor);
static int ze_mm_subscribe(struct ofi_mem_monitor *monitor, const void *addr,
			   size_t len, union ofi_mr_hmem_info *hmem_info);
static bool ze_mm_subscription_live(struct ofi_mem_monitor *monitor,
				    const void *addr, size_t len);
static bool ze_mm_valid(struct ofi_mem_monitor *monitor,
			const struct ofi_mr_info *info,
			struct ofi_mr_entry *entry);

/* Unsubscribe is a no-op: many MR cache entries may share one allocation,
 * and the allocation stays monitored until the driver reports it freed.
 */
static struct ze_mm ze_mm = {
	.mm = {
		.iface = FI_HMEM_ZE,
		.init = ze_mm_init,
		.cleanup = ze_mm_cleanup,
		.start = ze_mm_start,
		.stop = ze_mm_stop,
		.subscribe = ze_mm_subscribe,
		.unsubscribe = ofi_monitor_unsubscribe_no_op,
		.subscribe_unlocked = true,
		.subscription_live = ze_mm_subscription_live,
		.valid = ze_mm_valid,
		.name = "ze",
	},
};

struct ofi_mem_monitor *ze_monitor = &ze_mm.mm;

static int ze_rbmap_compare(struct ofi_rbmap *map, void *key, void *data)
{
	struct ze_mm_entry *entry = data;
	struct iovec *iov = key;

	if (ofi_iov_left(&entry->iov, iov))
		return -1;
	else if (ofi_iov_right(&entry->iov, iov))
		return 1;

	return 0;
}

/* Callers must hold ze_mm.lock. */
static struct ze_mm_entry *ze_mm_entry_find(const void *addr)
{
	struct ofi_rbnode *node;
	struct iovec iov = {
		.iov_base = (void *) addr,
		.iov_len = 1,
	};

	node = ofi_rbmap_find(ze_mm.tree, (void *) &iov);
	if (node)
		return node->data;
	return NULL;
}

/* Runs on the thread calling zeMemFree, before the memory is released.
 * Two stages so ze_mm.lock and mm_lock are never held together: detach the
 * entry under ze_mm.lock, then notify MR caches under mm_lock. A racing
 * unlocked subscribe either fails its subscription_live() recheck (the entry
 * is already detached) or has its published entry evicted by stage 2.
 */
static void ze_mm_free_cb(void *user_data)
{
	struct ze_mm_entry *entry = NULL;

	pthread_mutex_lock(&ze_mm.lock);
	if (ze_mm.tree)
		entry = ze_mm_entry_find(user_data);
	if (entry) {
		ofi_rbmap_delete(ze_mm.tree, entry->node);
		/* The registering thread still owns a pending entry. */
		if (entry->registering) {
			entry->invalidated = true;
			entry = NULL;
		}
	}
	pthread_mutex_unlock(&ze_mm.lock);

	if (!entry)
		return;

	pthread_rwlock_rdlock(&mm_list_rwlock);
	pthread_mutex_lock(&mm_lock);
	ofi_monitor_notify(ze_monitor, entry->iov.iov_base, entry->iov.iov_len);
	pthread_mutex_unlock(&mm_lock);
	pthread_rwlock_unlock(&mm_list_rwlock);

	/* free() can reenter the memhooks munmap intercept, which takes
	 * mm_lock, so free only after both locks are dropped.
	 */
	free(entry);
}

/* One callback per ZE allocation. Caller holds registration_lock, never
 * ze_mm.lock across ZE calls or allocation.
 */
static int ze_mm_entry_alloc(const void *addr, uint64_t id, struct iovec *iov)
{
	struct ze_mm_entry *entry;
	struct ofi_rbnode *node;
	void *base;
	size_t size;
	int ret;

	ret = ze_hmem_get_base_addr(addr, 0, &base, &size);
	if (ret)
		return ret;

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return -FI_ENOMEM;

	/* registration_lock keeps the tree alive; allocate outside ze_mm.lock. */
	node = ofi_rbnode_alloc(ze_mm.tree);
	if (!node) {
		free(entry);
		return -FI_ENOMEM;
	}

	entry->iov.iov_base = base;
	entry->iov.iov_len = size;
	entry->id = id;
	entry->registering = true;
	*iov = entry->iov;

	/* Publish a pending entry before the driver can invoke the callback. */
	pthread_mutex_lock(&ze_mm.lock);
	ret = ofi_rbmap_insert_at(ze_mm.tree, &entry->iov, entry, &entry->node,
				  node);
	pthread_mutex_unlock(&ze_mm.lock);
	if (ret) {
		free(node);
		free(entry);
		return ret;
	}

	ret = ze_hmem_register_free_cb(base, ze_mm_free_cb, base);

	pthread_mutex_lock(&ze_mm.lock);
	entry->registering = false;
	if (entry->invalidated)
		ret = -FI_EAGAIN;
	else if (ret)
		ofi_rbmap_delete(ze_mm.tree, entry->node);
	pthread_mutex_unlock(&ze_mm.lock);

	if (ret)
		free(entry);
	return ret;
}

static void ze_mm_init(struct ofi_mem_monitor *monitor)
{
	pthread_mutex_init(&ze_mm.lock, NULL);
	pthread_mutex_init(&ze_mm.registration_lock, NULL);
	ofi_monitor_init(monitor);
}

static void ze_mm_cleanup(struct ofi_mem_monitor *monitor)
{
	ofi_monitor_cleanup(monitor);
	pthread_mutex_destroy(&ze_mm.registration_lock);
	pthread_mutex_destroy(&ze_mm.lock);
}

static int ze_mm_start(struct ofi_mem_monitor *monitor)
{
	struct ofi_rbmap *tree;

	if (!ze_hmem_free_cb_supported()) {
		FI_INFO(&core_prov, FI_LOG_MR,
			"ZE free callback unavailable, validating cached MRs "
			"by allocation id\n");
		return FI_SUCCESS;
	}

	pthread_mutex_lock(&ze_mm.registration_lock);
	tree = ofi_rbmap_create(ze_rbmap_compare);
	pthread_mutex_lock(&ze_mm.lock);
	ze_mm.tree = tree;
	pthread_mutex_unlock(&ze_mm.lock);
	pthread_mutex_unlock(&ze_mm.registration_lock);

	return tree ? FI_SUCCESS : -FI_ENOMEM;
}

/* The driver keeps the registered callbacks; after this they find no entry
 * and return.
 */
static void ze_mm_stop(struct ofi_mem_monitor *monitor)
{
	struct ze_mm_entry *entry;
	struct ofi_rbmap *tree;
	struct ofi_rbnode *node;
	DEFINE_LIST(detached);

	pthread_mutex_lock(&ze_mm.registration_lock);
	pthread_mutex_lock(&ze_mm.lock);
	tree = ze_mm.tree;
	ze_mm.tree = NULL;
	while (tree && (node = ofi_rbmap_get_root(tree))) {
		entry = node->data;
		ofi_rbmap_delete(tree, node);
		dlist_insert_tail(&entry->entry, &detached);
	}
	pthread_mutex_unlock(&ze_mm.lock);

	while (!dlist_empty(&detached)) {
		dlist_pop_front(&detached, struct ze_mm_entry, entry, entry);
		free(entry);
	}
	if (tree)
		ofi_rbmap_destroy(tree);
	pthread_mutex_unlock(&ze_mm.registration_lock);
}

/* Monitors the whole ZE allocation containing addr, reusing the entry if
 * the allocation is already monitored. Runs without mm_lock
 * (subscribe_unlocked): the driver and the entry allocation may both call
 * malloc, which can reenter libfabric through the memhooks intercept.
 *
 * The allocation id is always recorded for valid().
 */
static int ze_mm_subscribe(struct ofi_mem_monitor *monitor, const void *addr,
			   size_t len, union ofi_mr_hmem_info *hmem_info)
{
	struct ze_mm_entry *entry, *stale = NULL;
	struct iovec iov;
	struct iovec mr_iov = {
		.iov_base = (void *) addr,
		.iov_len = len,
	};
	bool found;
	int ret;

	ret = ze_hmem_get_id(addr, &hmem_info->ze_id);
	if (ret || !ze_hmem_free_cb_supported())
		return ret;

	pthread_mutex_lock(&ze_mm.registration_lock);
	pthread_mutex_lock(&ze_mm.lock);
	if (!ze_mm.tree) {
		/* Racing start or stop; leave the MR uncached. */
		pthread_mutex_unlock(&ze_mm.lock);
		ret = -FI_EAGAIN;
		goto out;
	}
	entry = ze_mm_entry_find(addr);
	if (entry && entry->id != hmem_info->ze_id) {
		/* Our callback was displaced and never fired; the address
		 * now belongs to a new allocation. Register again.
		 */
		FI_DBG(&core_prov, FI_LOG_MR,
		       "ZE allocation at %p replaced without free callback\n",
		       entry->iov.iov_base);
		ofi_rbmap_delete(ze_mm.tree, entry->node);
		stale = entry;
		entry = NULL;
	}
	found = entry != NULL;
	if (found)
		iov = entry->iov;
	pthread_mutex_unlock(&ze_mm.lock);
	free(stale);

	ret = found ? FI_SUCCESS :
		      ze_mm_entry_alloc(addr, hmem_info->ze_id, &iov);
	if (ret)
		goto out;

	/* The free callback covers a single allocation. */
	if (!ofi_iov_within(&mr_iov, &iov)) {
		FI_WARN(&core_prov, FI_LOG_MR,
			"ZE buffer %p length %zu spans allocations\n", addr, len);
		ret = -FI_EINVAL;
	}
out:
	pthread_mutex_unlock(&ze_mm.registration_lock);
	return ret;
}

/* Called under mm_lock. A pending registration cannot authorize cache
 * publication.
 */
static bool ze_mm_subscription_live(struct ofi_mem_monitor *monitor,
				    const void *addr, size_t len)
{
	struct ze_mm_entry *entry = NULL;
	bool live;

	if (!ze_hmem_free_cb_supported())
		return true;

	pthread_mutex_lock(&ze_mm.lock);
	if (ze_mm.tree)
		entry = ze_mm_entry_find(addr);
	live = entry && !entry->registering;
	pthread_mutex_unlock(&ze_mm.lock);

	if (!live)
		FI_DBG(&core_prov, FI_LOG_MR,
		       "ZE buffer %p length %zu unmonitored before publication, "
		       "leaving MR uncached\n", addr, len);
	return live;
}

static bool ze_mm_valid(struct ofi_mem_monitor *monitor,
			const struct ofi_mr_info *info,
			struct ofi_mr_entry *entry)
{
	uint64_t id;
	int ret;

	/* Free callbacks evict entries at zeMemFree time, but a registration
	 * displaced by another library never fires, so the allocation id
	 * check stays as the safety net.
	 */
	ret = ze_hmem_get_id(entry->info.iov.iov_base, &id);
	if (ret)
		return false;

	return id == entry->hmem_info.ze_id;
}

#else

static int ze_mm_subscribe(struct ofi_mem_monitor *monitor, const void *addr,
			   size_t len, union ofi_mr_hmem_info *hmem_info)
{
	return -FI_ENOSYS;
}

static bool ze_mm_valid(struct ofi_mem_monitor *monitor,
			const struct ofi_mr_info *info,
			struct ofi_mr_entry *entry)
{
	return false;
}

static int ze_mm_start(struct ofi_mem_monitor *monitor)
{
	return -FI_ENOSYS;
}

static void ze_mm_stop(struct ofi_mem_monitor *monitor)
{
}

static struct ofi_mem_monitor ze_mm = {
	.iface = FI_HMEM_ZE,
	.init = ofi_monitor_init,
	.cleanup = ofi_monitor_cleanup,
	.start = ze_mm_start,
	.stop = ze_mm_stop,
	.subscribe = ze_mm_subscribe,
	.unsubscribe = ofi_monitor_unsubscribe_no_op,
	.valid = ze_mm_valid,
	.name = "ze",
};

struct ofi_mem_monitor *ze_monitor = &ze_mm;

#endif /* HAVE_ZE */
