/*
 * Copyright (c) Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the BSD license
 * below:
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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <rdma/fabric.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>

#include <shared.h>

fi_addr_t local_fi_addr = FI_ADDR_UNSPEC;

static int run(void)
{
	char temp[FT_MAX_CTRL_MSG];
	size_t addrlen = FT_MAX_CTRL_MSG;
	int ret;
	char *local_msg = "local message";
	char *remote_msg = "remote message";

	ret = ft_init_fabric();
	if (ret)
		goto err;

	ret = fi_getname(&ep->fid, temp, &addrlen);
	if (ret)
		goto err;

	ret = ft_av_insert(av, temp, 1, &local_fi_addr, 0, NULL);
	if (ret)
		goto err;

	// directed recv from remote
	FT_POST(fi_recv, ft_progress, rxcq, rx_seq, &rx_cq_cntr,
		"receive", ep, rx_ctx_arr[1].buf, strlen(remote_msg),
		rx_ctx_arr[1].desc, remote_fi_addr, &rx_ctx_arr[1].context);

	// directed recv from local
	FT_POST(fi_recv, ft_progress, rxcq, rx_seq, &rx_cq_cntr,
		"receive", ep, rx_ctx_arr[0].buf, strlen(local_msg),
		rx_ctx_arr[0].desc, local_fi_addr, &rx_ctx_arr[0].context);

	ft_sync();

	// send to local
	snprintf(tx_ctx_arr[0].buf, opts.transfer_size, local_msg);
	FT_POST(fi_send, ft_progress, txcq, tx_seq, &tx_cq_cntr, "transmit",
		ep, tx_ctx_arr[0].buf, strlen(local_msg), tx_ctx_arr[0].desc,
		local_fi_addr, &tx_ctx_arr[0].context);

	ft_sync();

	// send to remote
	snprintf(tx_ctx_arr[1].buf, opts.transfer_size, remote_msg);
	FT_POST(fi_send, ft_progress, txcq, tx_seq, &tx_cq_cntr, "transmit",
		ep, tx_ctx_arr[1].buf, strlen(remote_msg), tx_ctx_arr[1].desc,
		remote_fi_addr, &tx_ctx_arr[1].context);

	ft_sync();

	ret = ft_get_rx_comp(rx_seq);
	if (ret) {
		FT_PRINTERR("rx completion failure!", ret);
	}

	ret = ft_get_tx_comp(tx_seq);
	if (ret) {
		FT_PRINTERR("tx completion failure!", ret);
	}

	// validate data
	if (strncmp(rx_ctx_arr[0].buf, tx_ctx_arr[0].buf, strlen(local_msg))) {
		printf("invalid local message received! (Expected: %s, Actual: %s)\n",
		       local_msg, rx_ctx_arr[0].buf);
		ret = -FI_EIO;
	}

	if (strncmp(rx_ctx_arr[1].buf, tx_ctx_arr[1].buf, strlen(remote_msg))) {
		printf("invalid remote message received! (Expected: %s, Actual: %s)\n",
		       remote_msg, rx_ctx_arr[1].buf);
		ret = -FI_EIO;
	}

	ft_sync();

	if (!ret)
		printf("Success!\n");

	return ret;

err:
	FT_PRINTERR("unexpected address exchange error", ret);
	return ret;
}

int main(int argc, char **argv)
{
	int op, ret;

	opts = INIT_OPTS;
	opts.options |= FT_OPT_OOB_CTRL | FT_OPT_SIZE |
			FT_OPT_ALLOC_MULT_MR | FT_OPT_SKIP_PREPOST_RX;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	while ((op = getopt(argc, argv, "Uh" ADDR_OPTS INFO_OPTS)) != -1) {
		switch (op) {
		default:
			ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints, &opts);
			break;
		case 'U':
			hints->tx_attr->op_flags |= FI_DELIVERY_COMPLETE;
			break;
		case '?':
		case 'h':
			ft_usage(argv[0], "A simple RDM FI_DIRECTED_RECV example.");
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		opts.dst_addr = argv[optind];

	hints->ep_attr->type = FI_EP_RDM;
	hints->caps = FI_MSG | FI_DIRECTED_RECV;
	hints->mode = FI_CONTEXT;
	hints->domain_attr->mr_mode = opts.mr_mode;
	hints->addr_format = opts.address_format;

	ret = run();

	ft_free_res();
	return ft_exit_code(ret);
}
