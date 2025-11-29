#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/statvfs.h>

#include "cpe453fs.h"

struct Args
{
	int fd;
};

static void set_file_descriptor(void *args, int fd)
{
	struct Args *fs = (struct Args*)args;
	fs->fd = fd;
}

static int mygetattr(void *args, uint32_t block_num, struct stat *stbuf)
{
	// struct Args *fs = (struct Args*)args;
    return 0;
}

static int myreaddir(void *args, uint32_t block_num, void *buf, CPE453_readdir_callback_t cb)
{
	// struct Args *fs = (struct Args*)args;
    return 0;
}

static int myopen(void *args, uint32_t block_num)
{
	// struct Args *fs = (struct Args*)args;
    return 0;
}

static int myread(void *args, uint32_t block_num, char *buf, size_t size, off_t offset)
{
	// struct Args *fs = (struct Args*)args;
    return 0;
}

static int myreadlink(void *args, uint32_t block_num, char *buf, size_t size)
{
	// struct Args *fs = (struct Args*)args;
	return 0;
}


static uint32_t root_node(void *args)
{
	// struct Args *fs = (struct Args*)args;
	return 0;
}

#ifdef  __cplusplus
extern "C" {
#endif

struct cpe453fs_ops *CPE453_get_operations(void)
{
	static struct cpe453fs_ops ops;
	static struct Args args;
	memset(&ops, 0, sizeof(ops));
	ops.arg = &args;

	ops.getattr = mygetattr;
	ops.readdir = myreaddir;
	ops.open = myopen;
	ops.read = myread;
	ops.readlink = myreadlink;
	ops.root_node = root_node;
	ops.set_file_descriptor = set_file_descriptor;

	return &ops;
}

#ifdef  __cplusplus
}
#endif

