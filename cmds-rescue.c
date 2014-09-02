/*
 * Copyright (C) 2013 SUSE.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#define _XOPEN_SOURCE 500
#define _GNU_SOURCE 1

#include "kerncompat.h"

#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include "crc32c.h"
#include "ctree.h"
#include "extent_io.h"
#include "disk-io.h"
#include "commands.h"
#include "utils.h"
#include "volumes.h"

static const char * const rescue_cmd_group_usage[] = {
	"btrfs rescue <command> [options] <path>",
	NULL
};

int btrfs_recover_chunk_tree(char *path, int verbose, int yes);
int btrfs_recover_superblocks(char *path, int verbose, int yes);

const char * const cmd_chunk_recover_usage[] = {
	"btrfs rescue chunk-recover [options] <device>",
	"Recover the chunk tree by scanning the devices one by one.",
	"",
	"-y	Assume an answer of `yes' to all questions",
	"-v	Verbose mode",
	"-h	Help",
	NULL
};

const char * const cmd_super_recover_usage[] = {
	"btrfs rescue super-recover [options] <device>",
	"Recover bad superblocks from good copies",
	"",
	"-y	Assume an answer of `yes' to all questions",
	"-v	Verbose mode",
	NULL
};

int cmd_chunk_recover(int argc, char *argv[])
{
	int ret = 0;
	char *file;
	int yes = 0;
	int verbose = 0;

	while (1) {
		int c = getopt(argc, argv, "yvh");
		if (c < 0)
			break;
		switch (c) {
		case 'y':
			yes = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
		default:
			usage(cmd_chunk_recover_usage);
		}
	}

	argc = argc - optind;
	if (check_argc_exact(argc, 1))
		usage(cmd_chunk_recover_usage);

	file = argv[optind];

	ret = check_mounted(file);
	if (ret < 0) {
		fprintf(stderr, "Could not check mount status: %s\n",
			strerror(-ret));
		return 1;
	} else if (ret) {
		fprintf(stderr, "the device is busy\n");
		return 1;
	}

	ret = btrfs_recover_chunk_tree(file, verbose, yes);
	if (!ret) {
		fprintf(stdout, "Recover the chunk tree successfully.\n");
	} else if (ret > 0) {
		ret = 0;
		fprintf(stdout, "Abort to rebuild the on-disk chunk tree.\n");
	} else {
		fprintf(stdout, "Fail to recover the chunk tree.\n");
	}
	return ret;
}

/*
 * return codes:
 *   0 : All superblocks are valid, no need to recover
 *   1 : Usage or syntax error
 *   2 : Recover all bad superblocks successfully
 *   3 : Fail to Recover bad supeblocks
 *   4 : Abort to recover bad superblocks
 */
int cmd_super_recover(int argc, char **argv)
{
	int ret;
	int verbose = 0;
	int yes = 0;
	char *dname;

	while (1) {
		int c = getopt(argc, argv, "vy");
		if (c < 0)
			break;
		switch (c) {
		case 'v':
			verbose = 1;
			break;
		case 'y':
			yes = 1;
			break;
		default:
			usage(cmd_super_recover_usage);
		}
	}
	argc = argc - optind;
	if (check_argc_exact(argc, 1))
		usage(cmd_super_recover_usage);

	dname = argv[optind];
	ret = check_mounted(dname);
	if (ret < 0) {
		fprintf(stderr, "Could not check mount status: %s\n",
			strerror(-ret));
		return 1;
	} else if (ret) {
		fprintf(stderr, "the device is busy\n");
		return 1;
	}
	ret = btrfs_recover_superblocks(dname, verbose, yes);
	return ret;
}

const char * const cmd_rescue_find_root_usage[] = {
	"btrfs rescue find-root [options] <device>",
	"",
	"-o search_objectid",
	"-g search_generation",
	"-l search_level",
	NULL
};

struct btrfs_find_root_ctx {
	u16 csum_size;
	u64 search_objectid;
	u64 search_generation;
	unsigned long search_level;
	struct btrfs_root *root;
};

static int csum_block(struct btrfs_find_root_ctx *ctx, void *buf, u32 len)
{
	char *result;
	u32 crc = ~(u32)0;
	int ret = 0;

	result = malloc(ctx->csum_size * sizeof(char));
	if (!result) {
		fprintf(stderr, "No memory\n");
		return 1;
	}

	len -= BTRFS_CSUM_SIZE;
	crc = crc32c(crc, buf + BTRFS_CSUM_SIZE, len);
	btrfs_csum_final(crc, result);

	if (memcmp(buf, result, ctx->csum_size))
		ret = 1;
	free(result);
	return ret;
}

static int search_iobuf(struct btrfs_find_root_ctx *ctx, void *iobuf,
			size_t iobuf_size, off_t offset)
{
	u64 gen = ctx->search_generation;
	u64 objectid = ctx->search_objectid;
	u32 size = btrfs_super_nodesize(ctx->root->fs_info->super_copy);
	u8 level = ctx->search_level;
	size_t block_off = 0;

	while (block_off < iobuf_size) {
		void *block = iobuf + block_off;
		struct btrfs_header *header = block;
		u64 h_byte;
		u64 h_level;
		u64 h_gen;
		u64 h_owner;

//		printf("searching %Lu\n", offset + block_off);
		h_byte = btrfs_stack_header_bytenr(header);
		h_owner = btrfs_stack_header_owner(header);
		h_level = header->level;
		h_gen = btrfs_stack_header_generation(header);

		if (h_owner != objectid)
			goto next;
		if (h_byte != (offset + block_off))
			goto next;
		if (h_level < level)
			goto next;
		level = h_level;
		if (csum_block(ctx, block, size)) {
			fprintf(stderr, "Well block %Lu seems good, "
				"but the csum doesn't match\n",
				h_byte);
			goto next;
		}
		if (h_gen != gen) {
			fprintf(stderr, "Well block %Lu seems great, "
				"but generation doesn't match, "
				"have=%Lu, want=%Lu level %Lu\n", h_byte,
				h_gen, gen, h_level);
			goto next;
		}
		printf("Found tree root at %Lu gen %Lu level %Lu\n", h_byte,
		       h_gen, h_level);
		return 0;

next:
		block_off += size;
	}

	return 1;
}

static int read_physical(struct btrfs_find_root_ctx *ctx, int fd, u64 offset,
			 u64 bytenr, u64 len)
{
	char *iobuf = malloc(len);
	ssize_t done;
	size_t total_read = 0;
	int ret = 1;

	if (!iobuf) {
		fprintf(stderr, "No memory\n");
		return -1;
	}

	while (total_read < len) {
		done = pread64(fd, iobuf + total_read, len - total_read,
			       bytenr + total_read);
		if (done < 0) {
			fprintf(stderr, "Failed to read: %s\n",
				strerror(errno));
			ret = -1;
			goto out;
		}
		total_read += done;
	}

	ret = search_iobuf(ctx, iobuf, total_read, offset);
out:
	free(iobuf);
	return ret;
}

static int find_root(struct btrfs_find_root_ctx *ctx)
{
	struct btrfs_multi_bio *multi = NULL;
	struct btrfs_device *device;
	struct btrfs_root *root;
	u64 metadata_offset = 0;
	u64 metadata_size = 0;
	off_t offset = 0;
	off_t bytenr;
	int fd;
	int err;
	int ret = 1;

	root = ctx->root;

	printf("Super think's the tree root is at %Lu, chunk root %Lu\n",
	       btrfs_super_root(root->fs_info->super_copy),
	       btrfs_super_chunk_root(root->fs_info->super_copy));

	err = btrfs_next_metadata(&root->fs_info->mapping_tree,
				  &metadata_offset, &metadata_size);
	if (err)
		return ret;

	offset = metadata_offset;
	while (1) {
		u64 map_length = 4096;
		u64 type;

		if (offset >
		    btrfs_super_total_bytes(root->fs_info->super_copy)) {
			printf("Went past the fs size, exiting");
			break;
		}
		if (offset >= (metadata_offset + metadata_size)) {
			err = btrfs_next_metadata(&root->fs_info->mapping_tree,
						  &metadata_offset,
						  &metadata_size);
			if (err) {
				printf("No more metdata to scan, exiting\n");
				break;
			}
			offset = metadata_offset;
		}
		err = __btrfs_map_block(&root->fs_info->mapping_tree, READ,
				      offset, &map_length, &type,
				      &multi, 0, NULL);
		if (err) {
			offset += map_length;
			continue;
		}

		if (!(type & BTRFS_BLOCK_GROUP_METADATA)) {
			offset += map_length;
			kfree(multi);
			continue;
		}

		device = multi->stripes[0].dev;
		fd = device->fd;
		bytenr = multi->stripes[0].physical;
		kfree(multi);

		err = read_physical(ctx, fd, offset, bytenr, map_length);
		if (!err) {
			ret = 0;
			break;
		} else if (err < 0) {
			ret = err;
			break;
		}
		offset += map_length;
	}
	return ret;
}

int cmd_rescue_find_root(int argc, char *argv[])
{
	struct btrfs_find_root_ctx ctx;
	struct btrfs_root *root;
	int dev_fd;
	int ret;

	ctx.csum_size = 0;
	ctx.search_objectid = BTRFS_ROOT_TREE_OBJECTID;
	ctx.search_generation = 0;
	ctx.search_level = 0;

	while (1) {
		int c = getopt(argc, argv, "l:o:g:");

		if (c < 0)
			break;

		switch (c) {
		case 'o':
			ctx.search_objectid = arg_strtou64(optarg);
			break;
		case 'g':
			ctx.search_generation = arg_strtou64(optarg);
			break;
		case 'l':
			ctx.search_level = arg_strtou64(optarg);
			break;
		default:
			usage(cmd_rescue_find_root_usage);
		}
	}

	argc = argc - optind;
	if (check_argc_min(argc, 1))
		usage(cmd_rescue_find_root_usage);

	dev_fd = open(argv[optind], O_RDONLY);
	if (dev_fd < 0) {
		fprintf(stderr, "Failed to open device %s\n", argv[optind]);
		return 1;
	}

	/* TODO: OPEN_CTREE_RECOVER_SUPER by default ? */
	root = open_ctree_fd(dev_fd, argv[optind], 0,
			OPEN_CTREE_PARTIAL | OPEN_CTREE_EXCLUSIVE);
	close(dev_fd);

	if (!root) {
		fprintf(stderr, "Open ctree failed\n");
		return 1;
	}

	if (ctx.search_generation == 0)
		ctx.search_generation =
			btrfs_super_generation(root->fs_info->super_copy);

	ctx.csum_size = btrfs_super_csum_size(root->fs_info->super_copy);
	ctx.root = root;
	ret = find_root(&ctx);
	close_ctree(root);

	return !!ret;
}

const struct cmd_group rescue_cmd_group = {
	rescue_cmd_group_usage, NULL, {
		{ "chunk-recover", cmd_chunk_recover, cmd_chunk_recover_usage, NULL, 0},
		{ "super-recover", cmd_super_recover, cmd_super_recover_usage, NULL, 0},
		{ "find-root", cmd_rescue_find_root,
			cmd_rescue_find_root_usage, NULL, 0},
		{ 0, 0, 0, 0, 0 }
	}
};

int cmd_rescue(int argc, char **argv)
{
	return handle_command_group(&rescue_cmd_group, argc, argv);
}
