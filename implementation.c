#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include "cpe453fs.h"
#include <unistd.h>
#define BLOCK_SIZE 4096
#define INODE_CONTENT_SIZE 4028
#define EXTENT_CONTENT_SIZE 4084
#define DIRNAME_OFFSET 6
#define DIR_INODE_OFFSET 2
#define DIREXTENTS_DATA_SIZE 4088
#define FILEEXTENTS_DATA_SIZE 4084


//Block Type Magic Numbers
#define TYPE_SUPERBLOCK 1
#define TYPE_INODE 2
#define TYPE_DIR_EXTENT 3
#define TYPE_FILE_EXTENT 4
#define TYPE_FREE 5

//state struct (will likely need to hold more for read/write)
typedef struct {
  int fd;
} arg_t;

struct Super
{
  uint32_t type;
  uint32_t pattern[1021];
  uint32_t root;
  uint32_t free_head;
}__attribute__((packed));

struct Free
{
  uint32_t type;
  uint32_t next;
  uint8_t undefined[4088];
}__attribute__((packed));

struct Inode
{
  uint32_t type;
  uint16_t mode;
  uint16_t nlink;
  uint32_t uid;
  uint32_t gid;
  uint32_t rdev;
  uint32_t userflags;
  uint32_t atime_s;
  uint32_t atime_ns;
  uint32_t mtime_s;
  uint32_t mtime_ns;
  uint32_t stime_s;
  uint32_t stime_ns;
  uint64_t size;
  uint64_t numblocks;
  uint8_t contents[INODE_CONTENT_SIZE];
  uint32_t next;
}__attribute__((packed));

struct DirExtents
{
  uint32_t type;
  uint8_t contents[DIREXTENTS_DATA_SIZE];
  uint32_t next;
}__attribute__((packed));

struct FileExtents
{
  uint32_t type;
  uint32_t inode;
  uint8_t contents[FILEEXTENTS_DATA_SIZE];
  uint32_t next;
}__attribute__((packed));

static int findAndRemoveName(void* state, uint32_t parent_block, const char *name);

static uint32_t read_uint32(unsigned char *buf, int offset) {
  return *((uint32_t *)(buf + offset));
}

static uint16_t read_uint16(unsigned char *buf, int offset) {
  return *((uint16_t *)(buf + offset));
}

static int32_t allocate_block(void *state){
	arg_t *fs = (arg_t *)state;
	unsigned char block[BLOCK_SIZE];
	unsigned char fblock[BLOCK_SIZE];
	memset(block, 0, BLOCK_SIZE);
	memset(fblock, 0, BLOCK_SIZE);
	struct Super* super = (struct Super*)(block);
	struct Free* new = (struct Free*)(fblock);
	readblock(fs->fd, block, 0);
	if(super->type != 1){
		fprintf(stderr, "ERROR allocate_block() failed, superblock corrupted");
		return -EIO;
	}
	if(super->free_head != 0){
		uint32_t newbnum = super->free_head;
		readblock(fs->fd, fblock, newbnum);
		super->free_head = new->next;
		writeblock(fs->fd, (unsigned char*)super, 0);
		return newbnum;
	}
	struct stat file_info;
	if(fstat(fs->fd, &file_info) == -1){
		fprintf(stderr, "ERROR allocate_block() failed: fstat error");
		return -EIO;
	}
	uint32_t filesize = file_info.st_size;
	uint32_t new_block = filesize / BLOCK_SIZE;
	new->type = 5;
	new->next = 0;
	writeblock(fs->fd, (unsigned char*)new, new_block);
	return new_block;
}

static void set_file_descriptor(void *state, int fd) {
  arg_t *fs = (arg_t *)state;
  fs->fd = fd;
}

static uint32_t root_node(void *state) {
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, 0);
  uint32_t root = read_uint32(block, 4088);
  return root;
}

static int getattr(void *state, uint32_t block_num, struct stat *stbuf) {
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);

  uint32_t type = read_uint32(block, 0);
  if (type != TYPE_INODE) {
    return -ENOENT;
  }

  memset(stbuf, 0, sizeof(struct stat));

  stbuf->st_mode = read_uint16(block, 4);
  stbuf->st_nlink = read_uint16(block, 6);
  stbuf->st_uid = read_uint32(block, 8);
  stbuf->st_gid = read_uint32(block, 12);
  stbuf->st_rdev = read_uint32(block, 16);
  stbuf->st_atim.tv_sec = read_uint32(block, 24);
  stbuf->st_atim.tv_nsec = read_uint32(block, 28);
  stbuf->st_mtim.tv_sec = read_uint32(block, 32);
  stbuf->st_mtim.tv_nsec = read_uint32(block, 36);
  stbuf->st_ctim.tv_sec = read_uint32(block, 40);
  stbuf->st_ctim.tv_nsec = read_uint32(block, 44);
  stbuf->st_size = read_uint32(block, 48);
  stbuf->st_blocks = read_uint32(block, 56);
  stbuf->st_blksize = BLOCK_SIZE;

  return 0;
}

//helper for parsing directory entries in a block
static void parse_dir_entries(unsigned char *contents, int content_start,
int max_offset, void *buf, CPE453_readdir_callback_t cb) {
  int offset = content_start;

    while (offset + 6 < max_offset){
    uint16_t entry_len = read_uint16(contents, offset);

        if (entry_len == 0){
      break;
    }

    uint32_t entry_inode = read_uint32(contents, offset + 2);
    int name_len = entry_len - 6;
    char name[256];
    memcpy(name, contents + offset + 6, name_len);
    name[name_len] = '\0';
    cb(buf, name, entry_inode);
    offset += entry_len;
  }
}


static int readdir(void *state, uint32_t block_num, void *buf, CPE453_readdir_callback_t cb) {
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);
  uint32_t type = read_uint32(block, 0);
    if (type != TYPE_INODE){
    return -ENOTDIR;
  }
  uint32_t mode = read_uint32(block, 4);
    if (!S_ISDIR(mode)){
    return -ENOTDIR;
  }
  parse_dir_entries(block, 64, 4092, buf, cb);
  uint32_t next_extent = read_uint32(block, 4092);
    while (next_extent != 0){
    memset(block, 0, BLOCK_SIZE);
    readblock(fs->fd, block, next_extent);
    type = read_uint32(block, 0);
    if (type != TYPE_DIR_EXTENT) {
      return -1;
    }
    parse_dir_entries(block, 4, 4092, buf, cb);
    next_extent = read_uint32(block, 4092);
  }
  return 0;
}

static int open_file(void *state, uint32_t block_num){
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);
  uint32_t type = read_uint32(block, 0);
    if (type != TYPE_INODE){
    return -ENOENT;
  }
  uint32_t mode = read_uint32(block, 4);
    if (!S_ISREG(mode)){
    return -EISDIR;
  }
  return 0;
}

static int read_file(void *state, uint32_t block_num, char *buff, size_t size, off_t offset){
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);

  uint32_t file_size = read_uint32(block, 48);

    if (offset >= file_size){
    return 0;
  }

  if (offset + size > file_size) {
    size = file_size - offset;
  }

  int bytes_read = 0;
  int is_first_block = 1;
  off_t current_offset = offset;

  // Skip to the correct block based on offset
  if (current_offset >= INODE_CONTENT_SIZE) {
    current_offset -= INODE_CONTENT_SIZE;
    uint32_t next = read_uint32(block, 4092);

    // Skip through extent blocks
    while (next != 0 && current_offset >= EXTENT_CONTENT_SIZE) {
      current_offset -= EXTENT_CONTENT_SIZE;
      memset(block, 0, BLOCK_SIZE);
      readblock(fs->fd, block, next);
      next = read_uint32(block, 4092);
    }

    // If offset remaining read the extent block
    if (next != 0) {
      memset(block, 0, BLOCK_SIZE);
      readblock(fs->fd, block, next);
      is_first_block = 0;
    } else if (current_offset > 0) {
      return 0;
    }
  }

  // Read data from blocks
  while (bytes_read < size) {
    int content_start, content_size;

    if (is_first_block) {
      content_start = 64;
      content_size = INODE_CONTENT_SIZE;
    } else {
      content_start = 8;
      content_size = EXTENT_CONTENT_SIZE;
    }

    int available = content_size - current_offset;
    int to_read;
    if (size - bytes_read < available) {
      to_read = size - bytes_read;
    } else {
      to_read = available;
    }
    memcpy(buff + bytes_read, block + content_start + current_offset, to_read);
    bytes_read += to_read;
    current_offset = 0;

    if (bytes_read < size) {
      uint32_t next = read_uint32(block, 4092);
      if (next == 0) {
        break;
      }
      memset(block, 0, BLOCK_SIZE);
      readblock(fs->fd, block, next);
      is_first_block = 0;
    }
  }

  return bytes_read;
}

static int readlink_file(void *state, uint32_t block_num, char *buff, size_t buff_size) {
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);

  uint32_t mode = read_uint32(block, 4);
  if (!S_ISLNK(mode)) {
    return -EINVAL;
  }

  uint32_t link_size = read_uint32(block, 48);
  int copy_size;
    if (link_size < buff_size - 1){
    copy_size = link_size;
  } else {
    copy_size = buff_size - 1;
  }
  memcpy(buff, block + 64, copy_size);
  buff[copy_size] = '\0';

  return 0;
}

static int chmod_file(void *state, uint32_t block_num, mode_t new_mode) {
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);

    //check its an inode
  uint32_t type = read_uint32(block, 0);
  if (type != TYPE_INODE) {
    return -ENOENT;
  }

    //check current mode
  uint16_t old_mode = read_uint16(block, 4);
    uint16_t file_type = old_mode & S_IFMT; // find file type bits (needs to be preserved)
    uint16_t perms = new_mode & 07777; //remove type bits
    uint16_t updated_mode = file_type | perms; //combine filetype and perms

    //mode is at offset 4
  *((uint16_t *)(block + 4)) = updated_mode;
  writeblock(fs->fd, block, block_num);
  return 0;
}

static int chown_file(void *state, uint32_t block_num, uid_t new_uid, gid_t new_gid) {
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);

    //check its an inode
  uint32_t type = read_uint32(block, 0);
  if (type != TYPE_INODE) {
    return -ENOENT;
  }

    //write new uid (8 byte offset)
  *((uint32_t *)(block + 8)) = new_uid;
    //write new gid (12 byte offset)
  *((uint32_t *)(block + 12)) = new_gid;
  writeblock(fs->fd, block, block_num);
  return 0;
}

static int utimens(void *state, uint32_t block_num, const struct timespec tv[2]) {
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);

    //check its an inode
  uint32_t type = read_uint32(block, 0);
  if (type != TYPE_INODE) {
    return -ENOENT;
  }

    //tv[0] = access time
    //tv[1] = modification time
    //atime in seconds at 24 byte offset
  *((uint32_t *)(block + 24)) = tv[0].tv_sec;
    //atime in nanoseconds at 28 byte offset
  *((uint32_t *)(block + 28)) = tv[0].tv_nsec;
    //mtime seconds at 32 byte offset
  *((uint32_t *)(block + 32)) = tv[1].tv_sec;
    //mtime in nanoseconds at 36 byte offset
  *((uint32_t *)(block + 36)) = tv[1].tv_nsec;
  writeblock(fs->fd, block, block_num);
  return 0;
}

static int rmdir_dir(void *state, uint32_t block_num, const char *name) {
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);

    //parent must be directory inode
  struct Inode *parent = (struct Inode *)block;
  if (parent->type != TYPE_INODE) {
    return -ENOTDIR;
  }
    if (!S_ISDIR(parent->mode)){
    return -ENOTDIR;
  }

  // find directory entry in parent inode
  uint32_t target_inode = 0;
  int offset = 0;

  // check all names in parent inode
    while (offset + 6 < INODE_CONTENT_SIZE){
    uint16_t entry_len = read_uint16(parent->contents, offset);
        if (entry_len == 0) break;
    uint32_t entry_inode = read_uint32(parent->contents, offset + 2);
    int name_len = entry_len - 6;
        if (strncmp((char *)(parent->contents + offset + 6), name, name_len) == 0 && name[name_len] == '\0') {
      target_inode = entry_inode;
      break;
    }
    offset += entry_len;
  }

  // if not found in inode, search parent's extent blocks
  if (target_inode == 0) {
    uint32_t next_extent = parent->next;

    while (next_extent != 0) {
      unsigned char eblock[BLOCK_SIZE];
      memset(eblock, 0, BLOCK_SIZE);
      readblock(fs->fd, eblock, next_extent);

      struct DirExtents *extents = (struct DirExtents *)eblock;
      if (extents->type != TYPE_DIR_EXTENT) {
        return -EIO;
      }

      offset = 0;
      while (offset + 6 < DIREXTENTS_DATA_SIZE) {
        uint16_t entry_len = read_uint16(extents->contents, offset);
                if (entry_len == 0) break;

        uint32_t entry_inode = read_uint32(extents->contents, offset + 2);
        int name_len = entry_len - 6;

                if (strncmp((char *)(extents->contents + offset + 6), name, name_len) == 0 && 
            name[name_len] == '\0') {
          target_inode = entry_inode;
          break;
        }
        offset += entry_len;
      }

            if (target_inode != 0) break;
      next_extent = extents->next;
    }
  }

    if (target_inode == 0){
    return -ENOENT;
  }

  // read the directory's inode
  unsigned char target_block[BLOCK_SIZE];
  memset(target_block, 0, BLOCK_SIZE);
  readblock(fs->fd, target_block, target_inode);

  struct Inode *target = (struct Inode *)target_block;

  // make sure it's a directory
  if (target->type != TYPE_INODE) {
    return -ENOENT;
  }
  if (!S_ISDIR(target->mode)) {
    return -ENOTDIR;
  }

  // empty check
  int check_offset = 0;
    while (check_offset + 6 < INODE_CONTENT_SIZE){
    uint16_t entry_len = read_uint16(target->contents, check_offset);
    if (entry_len == 0) {
      break;
    }
    return -ENOTEMPTY;
  }

  // make sure there are no extent blocks
  if (target->next != 0) {
    return -ENOTEMPTY;
  }

  // free inode and add to free list
  unsigned char superblock[BLOCK_SIZE];
  readblock(fs->fd, superblock, 0);
  struct Super *super = (struct Super *)superblock;

  target->type = TYPE_FREE;
  ((struct Free *)target)->next = super->free_head;
  super->free_head = target_inode;

  writeblock(fs->fd, (unsigned char *)target, target_inode);
  writeblock(fs->fd, superblock, 0);

  // remove from parent dir
  int result = findAndRemoveName(state, block_num, name);
  if (result < 0) {
    return result;
  }

  // update parent directory mtime, nlink, and size
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);
  parent = (struct Inode *)block;

  uint32_t cur_time = (uint32_t)time(NULL);

  parent->mtime_s = cur_time;
  parent->mtime_ns = 0;
  parent->nlink--;

  writeblock(fs->fd, (unsigned char *)parent, block_num);

  return 0;
}

static int unlink_file(void *state, uint32_t block_num, const char *name){
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);

  // parent must be directory inode
  struct Inode *parent = (struct Inode *)block;
    if (parent->type != TYPE_INODE){
    return -ENOTDIR;
  }
    if (!S_ISDIR(parent->mode)){
    return -ENOTDIR;
  }

  // find file entry in parent dir
  uint32_t target_inode = 0;
  int offset = 0;

    while (offset + 6 < INODE_CONTENT_SIZE){
    uint16_t entry_len = read_uint16(parent->contents, offset);
        if (entry_len == 0) break;
    uint32_t entry_inode = read_uint32(parent->contents, offset + 2);
    int name_len = entry_len - 6;

        if (strncmp((char *)(parent->contents + offset + 6), name, name_len) == 0 && name[name_len] == '\0') {
      target_inode = entry_inode;
      break;
    }
    offset += entry_len;
  }

  // if not found in inode, search parent's extent blocks
  if (target_inode == 0) {
    uint32_t next_extent = parent->next;

    while (next_extent != 0) {
      unsigned char eblock[BLOCK_SIZE];
      memset(eblock, 0, BLOCK_SIZE);
      readblock(fs->fd, eblock, next_extent);

      struct DirExtents *extents = (struct DirExtents *)eblock;
      if (extents->type != TYPE_DIR_EXTENT) {
        return -EIO;
      }

      offset = 0;
      while (offset + 6 < DIREXTENTS_DATA_SIZE) {
        uint16_t entry_len = read_uint16(extents->contents, offset);
                if (entry_len == 0) break;

        uint32_t entry_inode = read_uint32(extents->contents, offset + 2);
        int name_len = entry_len - 6;

                if (strncmp((char *)(extents->contents + offset + 6), name, name_len) == 0 && 
            name[name_len] == '\0') {
          target_inode = entry_inode;
          break;
        }
        offset += entry_len;
      }

            if (target_inode != 0) break;
      next_extent = extents->next;
    }
  }

  if (target_inode == 0) {
    return -ENOENT;
  }

  // read file's inode
  unsigned char target_block[BLOCK_SIZE];
  memset(target_block, 0, BLOCK_SIZE);
  readblock(fs->fd, target_block, target_inode);

  struct Inode *target = (struct Inode *)target_block;

  // make sure it's an inode
  if (target->type != TYPE_INODE) {
    return -ENOENT;
  }
  if (S_ISDIR(target->mode)) {
    return -EISDIR;
  }

  uint32_t cur_time = (uint32_t)time(NULL);
  target->nlink--;

  // update ctime on target file
  target->stime_s = cur_time;
  target->stime_ns = 0;

    if (target->nlink == 0){
    // read superblock for free list management
    unsigned char superblock[BLOCK_SIZE];
    readblock(fs->fd, superblock, 0);
    struct Super *super = (struct Super *)superblock;

    uint32_t next_extent = target->next;
        while (next_extent != 0){
      unsigned char extent_block[BLOCK_SIZE];
      memset(extent_block, 0, BLOCK_SIZE);
      readblock(fs->fd, extent_block, next_extent);

      struct FileExtents *extent = (struct FileExtents *)extent_block;
      uint32_t next = extent->next;

      // add extent to free list
      struct Free *free_blk = (struct Free *)extent_block;
      free_blk->type = TYPE_FREE;
      free_blk->next = super->free_head;
      super->free_head = next_extent;
      writeblock(fs->fd, extent_block, next_extent);
      writeblock(fs->fd, superblock,
                 0); // Write superblock immediately after updating free_head

      next_extent = next;
    }

    // add inode to free list
    target->type = TYPE_FREE;
    ((struct Free *)target)->next = super->free_head;
    super->free_head = target_inode;
    writeblock(fs->fd, superblock,0); // Write superblock immediately after updating free_head
  }

  writeblock(fs->fd, (unsigned char *)target, target_inode);

  int result = findAndRemoveName(state, block_num, name);
  if (result < 0) {
    return result;
  }

  // update parent directory mtime and size
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);
  parent = (struct Inode *)block;

  parent->mtime_s = cur_time;
  parent->mtime_ns = 0;

  writeblock(fs->fd, (unsigned char *)parent, block_num);

  return 0;
}

static int mknod_file(void *state, uint32_t parent_block, const char *name, mode_t new_mode, dev_t new_dev) {
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, parent_block);

    //parent must be dir inode
  uint32_t type = read_uint32(block, 0);
  if (type != TYPE_INODE) {
    return -ENOTDIR;
  }
  uint32_t mode = read_uint32(block, 4);
    if(!S_ISDIR(mode)) {
    return -ENOTDIR;
  }
    //get UID and GID
  struct fuse_context *ctx = fuse_get_context();
  uid_t uid = ctx->uid;
  gid_t gid = ctx->gid;

    //find a free inode block
  unsigned char superblock[BLOCK_SIZE];
  memset(superblock, 0, BLOCK_SIZE);
  readblock(fs->fd, superblock, 0);
  struct Super *super = (struct Super *)superblock;
  if (super->type != 1) {
    return -EIO;
  }
  if (super->free_head == 0) {
    return -ENOSPC; // no space
  }
  uint32_t free_inode = super->free_head;
  unsigned char fblock[BLOCK_SIZE];
  memset(fblock, 0, BLOCK_SIZE);
  readblock(fs->fd, fblock, free_inode);
  struct Free *free_block = (struct Free *)fblock;
  if (free_block->type != TYPE_FREE) {
    return -EIO; // free list corrupted
  }
  // update freelist head
  super->free_head = free_block->next;
  writeblock(fs->fd, (unsigned char *)super, 0);
  // make the new inode
  unsigned char new_inode[BLOCK_SIZE];
  memset(new_inode, 0, BLOCK_SIZE);

  *((uint32_t *)(new_inode)) = TYPE_INODE;
  *((uint16_t *)(new_inode + 4)) = new_mode;
    *((uint16_t *)(new_inode + 6)) = 1; //nlinks = 1
  *((uint32_t *)(new_inode + 8)) = uid;
  *((uint32_t *)(new_inode + 12)) = gid;
  *((uint32_t *)(new_inode + 16)) = new_dev;
    //use current time
  uint32_t cur_time = (uint32_t)time(NULL);
  *((uint32_t *)(new_inode + 24)) = cur_time; // atime secs
  *((uint32_t *)(new_inode + 28)) = 0;        // nsecs
  *((uint32_t *)(new_inode + 32)) = cur_time; // mtime secs
  *((uint32_t *)(new_inode + 36)) = 0;        // nsecs
  *((uint32_t *)(new_inode + 40)) = cur_time; // ctime secs
  *((uint32_t *)(new_inode + 44)) = 0;        // nsecs
  *((uint64_t *)(new_inode + 48)) = 0;        // size = 0 (8 bytes)
  *((uint64_t *)(new_inode + 56)) = 1;        // numblocks = 1 (8 bytes)
  *((uint32_t *)(new_inode + 4092)) = 0;      // next extent = NULL

  writeblock(fs->fd, new_inode, free_inode);
    //add entry to parent dir
  int name_len = strlen(name);
  uint16_t entry_len = 6 + name_len;
  int offset = 64;
  while (offset + 6 < 4092) {
    uint16_t existing_len = read_uint16(block, offset);
        if (existing_len == 0){
      *((uint16_t *)(block + offset)) = entry_len;
      *((uint32_t *)(block + offset + 2)) = free_inode;
      memcpy(block + offset + 6, name, name_len);
      break;
    }
    offset += existing_len;
  }
  if (offset + 6 >= 4092) {
    //no space in parent inode: free the allocated inode
    //read superblock fresh to get current free_head
    memset(superblock, 0, BLOCK_SIZE);
    readblock(fs->fd, superblock, 0);
    super = (struct Super *)superblock;
    free_block->type = TYPE_FREE;
    free_block->next = super->free_head;
    super->free_head = free_inode;
    writeblock(fs->fd, (unsigned char *)free_block, free_inode);
    writeblock(fs->fd, (unsigned char *)super, 0);
    return -ENOSPC;
  }
  
  // update parent directory inode
  struct Inode *parent = (struct Inode *)block;
  parent->size += entry_len;
  parent->mtime_s = cur_time;
  parent->mtime_ns = 0;
  parent->stime_s = cur_time;
  parent->stime_ns = 0;
  
  writeblock(fs->fd, block, parent_block);
  return 0;
}

int32_t findExistingName(void* state, uint32_t parent_block, const char *name){
	arg_t *fs = (arg_t*)state;
  unsigned char iblock[BLOCK_SIZE];
  readblock(fs->fd, iblock, parent_block);
	struct Inode *inode = (struct Inode*)(iblock);
	if(inode->type != 2){
		fprintf(stderr, "ERROR findExistingName() failed: %u is not an Inode, type= %u", parent_block, inode->type);
    return -EINVAL;
  }
	if((inode->mode & S_IFMT) != S_IFDIR){
		fprintf(stderr, "ERROR findExistingName() failed: parent_block %u is not an Directory, mode= %u", parent_block, inode->mode);
    return -ENOTDIR;
  }
  int curr_offset = 0;
  uint16_t entrylen;
  int namelen = strlen(name);
  int32_t targetinode;
	while(curr_offset < INODE_CONTENT_SIZE - 7){
		entrylen = *(uint16_t*)&inode->contents[curr_offset];
		targetinode = *(int32_t*)&inode->contents[curr_offset + DIR_INODE_OFFSET];
		if(entrylen == 0){
      break;
    }
		if(namelen == entrylen - 6){
			if(memcmp(name, &inode->contents[curr_offset + DIRNAME_OFFSET], namelen) == 0){
        return targetinode;
      }
    }
    curr_offset += entrylen;
  }

  unsigned char eblock[BLOCK_SIZE];
  struct DirExtents *extents;
  uint32_t nextblock = inode->next;
	while(nextblock != 0){
    curr_offset = 0;
    readblock(fs->fd, eblock, nextblock);
		extents = (struct DirExtents*)(eblock);
		if(extents->type != 3){
			fprintf(stderr, "ERROR findExistingName() failed: block is not Directory Extents");
      return -EIO;
    }
		while(curr_offset < DIREXTENTS_DATA_SIZE - 7){
			entrylen = *(uint16_t*)&extents->contents[curr_offset];
			targetinode = *(int32_t*)&extents->contents[curr_offset + DIR_INODE_OFFSET];
			if(entrylen == 0){
        break;
      }
			if(namelen == entrylen - 6){
				if(memcmp(name, &extents->contents[curr_offset + DIRNAME_OFFSET], namelen) == 0){
          return targetinode;
        }
      }
      curr_offset += entrylen;
    }
    nextblock = extents->next;
  }
  return 0;
}

int insert_in_dir(unsigned char *contents, int region_size, int totallen, uint32_t child, const char *name, int namelen){
  int curr_offset = 0;
  uint16_t entrylen;

	while(curr_offset < region_size - 7){
    entrylen = *(uint16_t *)&contents[curr_offset];
		if(entrylen == 0){
			if(curr_offset + totallen <= region_size){
				*(uint16_t*)&contents[curr_offset] = totallen;
				*(uint32_t*)&contents[curr_offset + DIR_INODE_OFFSET] = child;
        memcpy(&contents[curr_offset + DIRNAME_OFFSET], name, namelen);
        return 1;
      }
      break;
    }
    curr_offset += entrylen;
  }
  return 0;
}

static int symlink_file(void* state, uint32_t parent_block, const char *name, const char *link_dest){
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  readblock(fs->fd, block, parent_block);
	struct Inode *inode = (struct Inode*)(block);
    if(inode->type != 2){
		fprintf(stderr, "ERROR symlink() failed: parent_block %u is not an Inode, type= %u", parent_block, inode->type);
    return -EINVAL;
  }
	if((inode->mode & S_IFMT) != S_IFDIR){
		fprintf(stderr, "ERROR symlink() failed: parent_block %u is not an Directory, mode= %u", parent_block, inode->mode);
    return -ENOTDIR;
  }

  int res = findExistingName(state, parent_block, name);
	if(res > 0){
    return -EEXIST;
	} else if (res < 0){
    return res;
  }

  unsigned char superblock[BLOCK_SIZE];
  readblock(fs->fd, superblock, 0);
	struct Super *super = (struct Super*)(superblock);
	if(super->type != 1){
    fprintf(stderr, "ERROR symlink() failed: superblock corrupted");
    return -EIO;
  }
	if(super->free_head == 0){
    fprintf(stderr, "ERROR symlink() failed: No free block");
    return -ENOSPC;
  }
  uint32_t freeblock_num = super->free_head;
  unsigned char fblock[BLOCK_SIZE];
  readblock(fs->fd, fblock, freeblock_num);
	struct Free *free_block = (struct Free*)(fblock);
	if(free_block->type != 5){
    fprintf(stderr, "ERROR symlink() failed: free list corrupted");
    return -EIO;
  }
  super->free_head = free_block->next;
  writeblock(fs->fd, (unsigned char *)super, 0);

	//build new inode from free_block
	struct Inode *new_inode = (struct Inode*)(free_block);
  struct fuse_context *ctx = fuse_get_context();
  uint64_t link_len = strlen(link_dest);
	if(link_len > 4088){
    fprintf(stderr, "ERROR symlink() failed: file destination too long");
    //free the inode we allocated
    readblock(fs->fd, superblock, 0);
    super = (struct Super *)superblock;
    struct Free *f = (struct Free *)new_inode;
    f->type = TYPE_FREE;
    f->next = super->free_head;
    super->free_head = freeblock_num;
    writeblock(fs->fd, (unsigned char *)f, freeblock_num);
    writeblock(fs->fd, (unsigned char *)super, 0);
    return -ENAMETOOLONG;
  }
  
  uid_t uid = ctx->uid;
  gid_t gid = ctx->gid;
  new_inode->type = 2;
  new_inode->mode = (S_IFLNK | 0777);
  new_inode->nlink = 1;
  new_inode->uid = uid;
  new_inode->gid = gid;
  new_inode->rdev = 0;
  new_inode->userflags = 0;
  uint32_t curr_time = (uint32_t)time(NULL);
  new_inode->atime_s = curr_time;
  new_inode->atime_ns = 0;
  new_inode->mtime_s = curr_time;
  new_inode->mtime_ns = 0;
  new_inode->stime_s = curr_time;
  new_inode->stime_ns = 0;
  new_inode->size = link_len;
  new_inode->numblocks = 1;
  new_inode->next = 0;
  memcpy(new_inode->contents, link_dest, link_len);
  
  writeblock(fs->fd, (unsigned char *)new_inode, freeblock_num);

  int namelen = strlen(name);
  int totallen = namelen + 6;
  if (totallen > DIREXTENTS_DATA_SIZE) {
    fprintf(stderr, "ERROR symlink() failed: name too long");
    //free the inode we allocated
    readblock(fs->fd, superblock, 0);
    super = (struct Super *)superblock;
    struct Free *f = (struct Free *)new_inode;
    f->type = TYPE_FREE;
    f->next = super->free_head;
    super->free_head = freeblock_num;
    writeblock(fs->fd, (unsigned char *)f, freeblock_num);
    writeblock(fs->fd, (unsigned char *)super, 0);
    return -ENAMETOOLONG;
  }

  //try to insert in parent inode first
  int slotfound = 0;
  readblock(fs->fd, block, parent_block);
  inode = (struct Inode *)block;
  int ret = insert_in_dir(inode->contents, INODE_CONTENT_SIZE, totallen,
  freeblock_num, name, namelen);
  if(ret == 1){
    slotfound = 1;
    inode->mtime_s = curr_time;
    inode->mtime_ns = 0;
    inode->size += totallen;
    inode->stime_s = curr_time;
    inode->stime_ns = 0;
    writeblock(fs->fd, (unsigned char*)inode, parent_block);
    return 0;
  }

  //try existing extent blocks
  uint32_t extentsblocknum = inode->next;
  unsigned char eblock[BLOCK_SIZE];
  
  while (extentsblocknum != 0 && slotfound == 0) {
    readblock(fs->fd, eblock, extentsblocknum);
    struct DirExtents *extents = (struct DirExtents *)eblock;
    if (extents->type != 3) {
      fprintf(stderr,
              "ERROR symlink() failed: extents is not a directory extents");
      //free the inode we allocated
      readblock(fs->fd, superblock, 0);
      super = (struct Super *)superblock;
      struct Free *f = (struct Free *)new_inode;
      f->type = TYPE_FREE;
      f->next = super->free_head;
      super->free_head = freeblock_num;
      writeblock(fs->fd, (unsigned char *)f, freeblock_num);
      writeblock(fs->fd, (unsigned char *)super, 0);
      return -EINVAL;
    }

    ret = insert_in_dir(extents->contents, DIREXTENTS_DATA_SIZE, totallen,
                        freeblock_num, name, namelen);
    if (ret == 1) {
      slotfound = 1;
      writeblock(fs->fd, (unsigned char *)extents, extentsblocknum);
      readblock(fs->fd, block, parent_block);
      inode = (struct Inode *)block;
      inode->mtime_s = curr_time;
      inode->mtime_ns = 0;
      inode->stime_s = curr_time;
      inode->stime_ns = 0;
      inode->size += totallen;
      writeblock(fs->fd, (unsigned char *)inode, parent_block);
      return 0;
    }
    extentsblocknum = extents->next;
  }
  
  // new extent
  if (slotfound == 0) {
    readblock(fs->fd, superblock, 0);
    super = (struct Super *)superblock;
    
    if (super->free_head == 0) {
      fprintf(stderr, "ERROR symlink() failed: no free blocks for extent");
      //free the inode we allocated
      readblock(fs->fd, superblock, 0);
      super = (struct Super *)superblock;
      struct Free *f = (struct Free *)new_inode;
      f->type = TYPE_FREE;
      f->next = super->free_head;
      super->free_head = freeblock_num;
      writeblock(fs->fd, (unsigned char *)f, freeblock_num);
      writeblock(fs->fd, (unsigned char *)super, 0);
      return -ENOSPC;
    }
    
    uint32_t new_extent_num = super->free_head;
    unsigned char extent_block[BLOCK_SIZE];
    readblock(fs->fd, extent_block, new_extent_num);
    struct Free *free_extent = (struct Free *)extent_block;
    super->free_head = free_extent->next;
    writeblock(fs->fd, superblock, 0);
    
    //initialize new extent
    struct DirExtents *new_extent = (struct DirExtents *)extent_block;
    new_extent->type = 3;
    new_extent->next = 0;
    memset(new_extent->contents, 0, DIREXTENTS_DATA_SIZE);
    
    //insert the entry
    ret = insert_in_dir(new_extent->contents, DIREXTENTS_DATA_SIZE, totallen,
                        freeblock_num, name, namelen);
    if (ret != 1) {
      fprintf(stderr, "ERROR symlink() failed: couldn't insert in new extent");
      return -EIO;
    }
    
    writeblock(fs->fd, (unsigned char *)new_extent, new_extent_num);
    
    //link the extent to parent
    readblock(fs->fd, block, parent_block);
    inode = (struct Inode *)block;

    if (inode->next == 0) {
      inode->next = new_extent_num;
    } else {
      uint32_t tail = inode->next;
      unsigned char tail_block[BLOCK_SIZE];
      while (1) {
        readblock(fs->fd, tail_block, tail);
        struct DirExtents *tail_extent = (struct DirExtents *)tail_block;
        if (tail_extent->next == 0) {
          tail_extent->next = new_extent_num;
          writeblock(fs->fd, tail_block, tail);
          break;
        }
        tail = tail_extent->next;
      }
    }
    
    inode->numblocks++;
    inode->mtime_s = curr_time;
    inode->mtime_ns = 0;
    inode->stime_s = curr_time;
    inode->stime_ns = 0;
    inode->size += totallen;
    writeblock(fs->fd, (unsigned char *)inode, parent_block);
  }
  return 0;
}

static int mkdir_file(void* state, uint32_t parent_block, const char *name, mode_t new_mode){
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  readblock(fs->fd, block, parent_block);
	struct Inode *inode = (struct Inode*)(block);
    if(inode->type != 2){
		fprintf(stderr, "ERROR mkdir() failed: parent_block %u is not an Inode, type= %u", parent_block, inode->type);
    return -EINVAL;
  }
	if((inode->mode & S_IFMT) != S_IFDIR){
		fprintf(stderr, "ERROR mkdir() failed: parent_block %u is not an Directory, mode= %u", parent_block, inode->mode);
    return -ENOTDIR;
  }

  int res = findExistingName(state, parent_block, name);
	if(res > 0){
    return -EEXIST;
	} else if (res < 0){
    return res;
  }
  unsigned char superblock[BLOCK_SIZE];
  readblock(fs->fd, superblock, 0);
	struct Super *super = (struct Super*)(superblock);
	if(super->type != 1){
    fprintf(stderr, "ERROR mkdir() failed: superblock corrupted");
    return -EIO;
  }
	if(super->free_head == 0){
    fprintf(stderr, "ERROR mkdir() failed: No free block");
    return -ENOSPC;
  }
  uint32_t freeblock_num = super->free_head;
  unsigned char fblock[BLOCK_SIZE];
  readblock(fs->fd, fblock, freeblock_num);
	struct Free *free_block = (struct Free*)(fblock);
	if(free_block->type != 5){
    fprintf(stderr, "ERROR mkdir() failed: free list corrupted");
    return -EIO;
  }
  super->free_head = free_block->next;
  writeblock(fs->fd, (unsigned char *)super, 0);


  struct Inode *new_inode = (struct Inode *)(free_block);
  struct fuse_context *ctx = fuse_get_context();
  uid_t uid = ctx->uid;
  gid_t gid = ctx->gid;
  new_inode->type = 2;
  mode_t perms = new_mode & 0777;
  new_inode->mode = (S_IFDIR | perms);
  new_inode->nlink = 2;
  new_inode->uid = uid;
  new_inode->gid = gid;
  new_inode->rdev = 0;
  new_inode->userflags = 0;
  uint32_t curr_time = (uint32_t)time(NULL);
  new_inode->atime_s = curr_time;
  new_inode->atime_ns = 0;
  new_inode->mtime_s = curr_time;
  new_inode->mtime_ns = 0;
  new_inode->stime_s = curr_time;
  new_inode->stime_ns = 0;
  new_inode->size = 0;
  new_inode->numblocks = 1;
  new_inode->next = 0;
  memset(new_inode->contents, 0, INODE_CONTENT_SIZE);
  
  //write the new inode to disk before trying to add to parent in case of failure
  writeblock(fs->fd, (unsigned char *)new_inode, freeblock_num);

  int namelen = strlen(name);
  int totallen = namelen + 6;
	if(totallen > DIREXTENTS_DATA_SIZE){
    fprintf(stderr, "ERROR mkdir() failed: name too long");
    // Free the inode we allocated
    readblock(fs->fd, superblock, 0);
    super = (struct Super *)superblock;
    struct Free *f = (struct Free *)new_inode;
    f->type = TYPE_FREE;
    f->next = super->free_head;
    super->free_head = freeblock_num;
    writeblock(fs->fd, (unsigned char *)f, freeblock_num);
    writeblock(fs->fd, (unsigned char *)super, 0);
    return -ENAMETOOLONG;
  }

  // Try to insert in parent inode first
  int slotfound = 0;
  readblock(fs->fd, block, parent_block);
  inode = (struct Inode *)block;
  int ret = insert_in_dir(inode->contents, INODE_CONTENT_SIZE, totallen,
  freeblock_num, name, namelen);
  if(ret == 1){
    slotfound = 1;
    inode->mtime_s = curr_time;
    inode->mtime_ns = 0;
    inode->size += totallen;
    inode->nlink++;
    inode->stime_s = curr_time;
    inode->stime_ns = 0;
    writeblock(fs->fd, (unsigned char *)inode, parent_block);
    return 0;
  }
  uint32_t extentsblocknum = inode->next;
  unsigned char eblock[BLOCK_SIZE];

  while (extentsblocknum != 0 && slotfound == 0) {
    readblock(fs->fd, eblock, extentsblocknum);
    struct DirExtents *extents = (struct DirExtents *)eblock;
    if(extents->type != 3){
      fprintf(stderr, "ERROR mkdir() failed: extents is not a directory extents");
      // Free the inode we allocated
      readblock(fs->fd, superblock, 0);
      super = (struct Super *)superblock;
      struct Free *f = (struct Free *)new_inode;
      f->type = TYPE_FREE;
      f->next = super->free_head;
      super->free_head = freeblock_num;
      writeblock(fs->fd, (unsigned char *)f, freeblock_num);
      writeblock(fs->fd, (unsigned char *)super, 0);
      return -EINVAL;
    }
    
    ret = insert_in_dir(extents->contents, DIREXTENTS_DATA_SIZE, totallen,
                        freeblock_num, name, namelen);
    if (ret == 1) {
      slotfound = 1;
      writeblock(fs->fd, (unsigned char *)extents, extentsblocknum);
      readblock(fs->fd, block, parent_block);
      inode = (struct Inode *)block;
      inode->mtime_s = curr_time;
      inode->mtime_ns = 0;
      inode->size += totallen;
      inode->nlink++;
      inode->stime_s = curr_time;
      inode->stime_ns = 0;
      writeblock(fs->fd, (unsigned char *)inode, parent_block);
      return 0;
    }
    
    extentsblocknum = extents->next;
  }
  if (slotfound == 0) {
    readblock(fs->fd, superblock, 0);
    super = (struct Super *)superblock;
    
    if (super->free_head == 0) {
      fprintf(stderr, "ERROR mkdir() failed: no free blocks for extent");
      readblock(fs->fd, superblock, 0);
      super = (struct Super *)superblock;
      struct Free *f = (struct Free *)new_inode;
      f->type = TYPE_FREE;
      f->next = super->free_head;
      super->free_head = freeblock_num;
      writeblock(fs->fd, (unsigned char *)f, freeblock_num);
      writeblock(fs->fd, (unsigned char *)super, 0);
      return -ENOSPC;
    }
    
    uint32_t new_extent_num = super->free_head;
    unsigned char extent_block[BLOCK_SIZE];
    readblock(fs->fd, extent_block, new_extent_num);
    struct Free *free_extent = (struct Free *)extent_block;
    super->free_head = free_extent->next;
    writeblock(fs->fd, superblock, 0);
    
    //new extent
    struct DirExtents *new_extent = (struct DirExtents *)extent_block;
    new_extent->type = 3;
    new_extent->next = 0;
    memset(new_extent->contents, 0, DIREXTENTS_DATA_SIZE);
    
    ret = insert_in_dir(new_extent->contents, DIREXTENTS_DATA_SIZE, totallen,
                        freeblock_num, name, namelen);
    if (ret != 1) {
      fprintf(stderr, "ERROR mkdir() failed: couldn't insert in new extent");
      return -EIO;
    }
    
    writeblock(fs->fd, (unsigned char *)new_extent, new_extent_num);
    readblock(fs->fd, block, parent_block);
    inode = (struct Inode *)block;
    
    if (inode->next == 0) {
      inode->next = new_extent_num;
    } else {
      uint32_t tail = inode->next;
      unsigned char tail_block[BLOCK_SIZE];
      while (1) {
        readblock(fs->fd, tail_block, tail);
        struct DirExtents *tail_extent = (struct DirExtents *)tail_block;
        if (tail_extent->next == 0) {
          tail_extent->next = new_extent_num;
          writeblock(fs->fd, tail_block, tail);
          break;
        }
        tail = tail_extent->next;
      }
    }
    
    inode->numblocks++;
    inode->mtime_s = curr_time;
    inode->mtime_ns = 0;
    inode->size += totallen;
    inode->nlink++;
    inode->stime_s = curr_time;
    inode->stime_ns = 0;
    writeblock(fs->fd, (unsigned char *)inode, parent_block);
  }
  return 0;
}

int mylink(void *state, uint32_t parent_block, const char *name, uint32_t dest_block){
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  readblock(fs->fd, block, parent_block);
	struct Inode *inode = (struct Inode*)(block);
    if(inode->type != 2){
		fprintf(stderr, "ERROR link() failed: parent_block %u is not an Inode, type= %u", parent_block, inode->type);
    return -EINVAL;
  }
	if((inode->mode & S_IFMT) != S_IFDIR){
		fprintf(stderr, "ERROR link() failed: parent_block %u is not an Directory, mode= %u", parent_block, inode->mode);
    return -ENOTDIR;
  }

  int res = findExistingName(state, parent_block, name);
	if(res > 0){
    return -EEXIST;
	} else if (res < 0){
    return res;
  }
  unsigned char dblock[BLOCK_SIZE];
  readblock(fs->fd, dblock, dest_block);
	struct Inode *destinode = (struct Inode*)(dblock);
	if(destinode->type != 2){
		fprintf(stderr, "ERROR link() failed: dest_block %u is not an Inode, type= %u", dest_block, destinode->type);
    return -EINVAL;
  }
  destinode->nlink++;
  writeblock(fs->fd, (unsigned char *)destinode, dest_block);

  int namelen = strlen(name);
  int totallen = namelen + 6;
	if(totallen > DIREXTENTS_DATA_SIZE){
    fprintf(stderr, "ERROR link() failed: name too long");
    //decrement nlink back
    destinode->nlink--;
    writeblock(fs->fd, (unsigned char *)destinode, dest_block);
    return -ENAMETOOLONG;
  }

  int slotfound = 0;
  uint32_t curr_time = (uint32_t)time(NULL);
	int ret = insert_in_dir(inode->contents, INODE_CONTENT_SIZE, totallen, dest_block, name, namelen);
	if(ret == 1){
    slotfound = 1;
    inode->mtime_s = curr_time;
    inode->mtime_ns = 0;
    inode->size += totallen;
    inode->stime_s = curr_time;
    inode->stime_ns = 0;
    writeblock(fs->fd, (unsigned char *)inode, parent_block);
    return 0;
  }
  uint32_t extentsblocknum = inode->next;
  unsigned char eblock[BLOCK_SIZE];
  
  while (extentsblocknum != 0 && slotfound == 0) {
    readblock(fs->fd, eblock, extentsblocknum);
    struct DirExtents *extents = (struct DirExtents *)eblock;
    if(extents->type != 3){
      fprintf(stderr, "ERROR link() failed: extents is not a directory extents");
      //decrement nlink back
      readblock(fs->fd, dblock, dest_block);
      destinode = (struct Inode *)dblock;
      destinode->nlink--;
      writeblock(fs->fd, (unsigned char *)destinode, dest_block);
      return -EINVAL;
    }

    ret = insert_in_dir(extents->contents, DIREXTENTS_DATA_SIZE, totallen,
                        dest_block, name, namelen);
    if (ret == 1) {
      slotfound = 1;
      writeblock(fs->fd, (unsigned char *)extents, extentsblocknum);
      readblock(fs->fd, block, parent_block);
      inode = (struct Inode *)block;
      inode->mtime_s = curr_time;
      inode->mtime_ns = 0;
      inode->size += totallen;
      inode->stime_s = curr_time;
      inode->stime_ns = 0;
      writeblock(fs->fd, (unsigned char *)inode, parent_block);
      return 0;
    }
    extentsblocknum = extents->next;
  }
  
  if (slotfound == 0) {
    unsigned char superblock[BLOCK_SIZE];
    readblock(fs->fd, superblock, 0);
    struct Super *super = (struct Super *)superblock;
    
    if (super->free_head == 0) {
      fprintf(stderr, "ERROR link() failed: no free blocks");
      //decrement nlink since we incremented it earlier but failed to create the link
      readblock(fs->fd, dblock, dest_block);
      destinode = (struct Inode *)dblock;
      destinode->nlink--;
      writeblock(fs->fd, (unsigned char *)destinode, dest_block);
      return -ENOSPC;
    }
    
    uint32_t new_extent_num = super->free_head;
    unsigned char extent_block[BLOCK_SIZE];
    readblock(fs->fd, extent_block, new_extent_num);
    struct Free *free_extent = (struct Free *)extent_block;
    if (free_extent->type != 5) {
      fprintf(stderr, "ERROR link() failed: free list corrupted");
      //decrement nlink back
      readblock(fs->fd, dblock, dest_block);
      destinode = (struct Inode *)dblock;
      destinode->nlink--;
      writeblock(fs->fd, (unsigned char *)destinode, dest_block);
      return -EIO;
    }
    
    super->free_head = free_extent->next;
    writeblock(fs->fd, superblock, 0);

    struct DirExtents *new_extent = (struct DirExtents *)extent_block;
    new_extent->type = 3;
    new_extent->next = 0;
    memset(new_extent->contents, 0, DIREXTENTS_DATA_SIZE);
    
    ret = insert_in_dir(new_extent->contents, DIREXTENTS_DATA_SIZE, totallen,
                        dest_block, name, namelen);
    if (ret != 1) {
      fprintf(stderr, "ERROR link() failed: couldn't insert in new extent");
      return -EIO;
    }
    
    writeblock(fs->fd, (unsigned char *)new_extent, new_extent_num);
    
    // Link the extent to parent
    readblock(fs->fd, block, parent_block);
    inode = (struct Inode *)block;
    
    // Find tail of extent chain
    if (inode->next == 0) {
      inode->next = new_extent_num;
    } else {
      uint32_t tail = inode->next;
      unsigned char tail_block[BLOCK_SIZE];
      while (1) {
        readblock(fs->fd, tail_block, tail);
        struct DirExtents *tail_extent = (struct DirExtents *)tail_block;
        if (tail_extent->next == 0) {
          tail_extent->next = new_extent_num;
          writeblock(fs->fd, tail_block, tail);
          break;
        }
        tail = tail_extent->next;
      }
    }
    
    inode->numblocks++;
    inode->mtime_s = curr_time;
    inode->mtime_ns = 0;
    inode->size += totallen;
    inode->stime_s = curr_time;
    inode->stime_ns = 0;
    writeblock(fs->fd, (unsigned char *)inode, parent_block);
  }
  return 0;
}

int findAndRemoveName(void* state, uint32_t parent_block, const char *name){
	//returns the removed entries inode if found
	arg_t *fs = (arg_t*)state;
  unsigned char iblock[BLOCK_SIZE];
  uint32_t curr_time = (uint32_t)time(NULL);
  readblock(fs->fd, iblock, parent_block);
	struct Inode *inode = (struct Inode*)(iblock);
	if(inode->type != 2){
		fprintf(stderr, "ERROR findAndRemoveName() failed: %u is not an Inode, type= %u", parent_block, inode->type);
    return -EINVAL;
  }
	if((inode->mode & S_IFMT) != S_IFDIR){
		fprintf(stderr, "ERROR findFindAndRemoveName() failed: parent_block %u is not an Directory, mode= %u", parent_block, inode->mode);
    return -ENOTDIR;
  }
  int curr_offset = 0;
  uint16_t entrylen;
  int namelen = strlen(name);
  int bytestomove;
	while(curr_offset < INODE_CONTENT_SIZE - 7){
		entrylen = *(uint16_t*)&inode->contents[curr_offset];
		if(entrylen == 0){
      break;
    }
		if(namelen == entrylen - 6){
			if(memcmp(name, &inode->contents[curr_offset + DIRNAME_OFFSET], namelen) == 0){
				//move the rest of the blocks contents up
        bytestomove = INODE_CONTENT_SIZE - (curr_offset + entrylen);
				memmove(&inode->contents[curr_offset], &inode->contents[curr_offset + entrylen], bytestomove);
        memset(&inode->contents[curr_offset + bytestomove], 0, entrylen);
        inode->size -= entrylen;
        inode->mtime_s = curr_time;
        inode->mtime_ns = 0;
        inode->stime_s = curr_time;
        inode->stime_ns = 0;
        writeblock(fs->fd, (unsigned char *)inode, parent_block);
        return 0;
      }
    }
    curr_offset += entrylen;
  }

  unsigned char eblock[BLOCK_SIZE];
  struct DirExtents *extents;
  uint32_t nextblock = inode->next;
  while (nextblock != 0) {
    curr_offset = 0;
    readblock(fs->fd, eblock, nextblock);
		extents = (struct DirExtents*)(eblock);
		if(extents->type != 3){
			fprintf(stderr, "ERROR findFindAndRemoveName() failed: block is not Directory Extents");
      return -EIO;
    }
		while(curr_offset < DIREXTENTS_DATA_SIZE - 7){
			entrylen = *(uint16_t*)&extents->contents[curr_offset];
			if(entrylen == 0){
        break;
      }
			if(namelen == entrylen - 6){
				if(memcmp(name, &extents->contents[curr_offset + DIRNAME_OFFSET], namelen) == 0){
          bytestomove = DIREXTENTS_DATA_SIZE - (curr_offset + entrylen);
					memmove(&extents->contents[curr_offset], &extents->contents[curr_offset + entrylen], bytestomove);
          memset(&extents->contents[curr_offset + bytestomove], 0, entrylen);
					writeblock(fs->fd, (unsigned char*)extents, nextblock);
          inode->size -= entrylen;
          inode->mtime_s = curr_time;
          inode->mtime_ns = 0;
          inode->stime_s = curr_time;
          inode->stime_ns = 0;
					writeblock(fs->fd, (unsigned char*)inode, parent_block);
          return 0;
        }
      }
      curr_offset += entrylen;
    }
    nextblock = extents->next;
  }
  fprintf(stderr, "ERROR findAndRemoveName() failed: target does not exist");
  return -ENOENT;
}


int myrename(void *state, uint32_t old_parent, const char *old_name, uint32_t new_parent, const char *new_name){
  arg_t *fs = (arg_t *)state;
  unsigned char oldblock[BLOCK_SIZE];
  readblock(fs->fd, oldblock, old_parent);
	struct Inode *oldinode = (struct Inode*)(oldblock);
    if(oldinode->type != 2){
		fprintf(stderr, "ERROR rename() failed: parent_block %u is not an Inode, type= %u", old_parent, oldinode->type);
    return -EINVAL;
  }
	if((oldinode->mode & S_IFMT) != S_IFDIR){
		fprintf(stderr, "ERROR rename() failed: parent_block %u is not an Directory, mode= %u", old_parent, oldinode->mode);
    return -ENOTDIR;
  }
  unsigned char newblock[BLOCK_SIZE];
  readblock(fs->fd, newblock, new_parent);
	struct Inode *newinode = (struct Inode*)(newblock);
    if(newinode->type != 2){
		fprintf(stderr, "ERROR rename() failed: parent_block %u is not an Inode, type= %u", new_parent, newinode->type);
    return -EINVAL;
  }
	if((newinode->mode & S_IFMT) != S_IFDIR){
		fprintf(stderr, "ERROR rename() failed: parent_block %u is not an Directory, mode= %u", new_parent, newinode->mode);
    return -ENOTDIR;
  }

  int res = findExistingName(state, new_parent, new_name);
	if(res > 0){
    return -EEXIST;
	} else if (res < 0){
    return res;
  }

  int32_t found = findExistingName(state, old_parent, old_name);
	if(found < 0){
    return found;
  }

  uint32_t child = (uint32_t)found;

  int namelen = strlen(new_name);
  int totallen = namelen + 6;
	if(totallen > DIREXTENTS_DATA_SIZE){
    fprintf(stderr, "ERROR rename() failed: name too long");
    return -ENAMETOOLONG;
  }

  int slotfound = 0;
  uint32_t curr_time = (uint32_t)time(NULL);
  readblock(fs->fd, newblock, new_parent);
  newinode = (struct Inode *)newblock;
  int ret = insert_in_dir(newinode->contents, INODE_CONTENT_SIZE, totallen, child, new_name, namelen);
	if(ret == 1){
    slotfound = 1;
    newinode->mtime_s = curr_time;
    newinode->mtime_ns = 0;
    newinode->size += totallen;
    newinode->stime_s = curr_time;
    newinode->stime_ns = 0;
    writeblock(fs->fd, (unsigned char *)newinode, new_parent);
    res = findAndRemoveName(state, old_parent, old_name);
    if (res < 0) {
      fprintf(stderr,
              "ERROR rename() failed: old_name doesn't exist in old parent block");
      return res;
    }
    return 0;
  }
  uint32_t extentsblocknum = newinode->next;
  unsigned char eblock[BLOCK_SIZE];
  while (extentsblocknum != 0 && slotfound == 0) {
    readblock(fs->fd, eblock, extentsblocknum);
    struct DirExtents *extents = (struct DirExtents *)eblock;
    if (extents->type != 3) {
      fprintf(stderr,
              "ERROR rename() failed: extents is not a directory extents");
      return -EINVAL;
    }

    ret = insert_in_dir(extents->contents, DIREXTENTS_DATA_SIZE, totallen,
                        child, new_name, namelen);
    if (ret == 1) {
      slotfound = 1;
      writeblock(fs->fd, (unsigned char *)extents, extentsblocknum);
      readblock(fs->fd, newblock, new_parent);
      newinode = (struct Inode *)newblock;
      newinode->mtime_s = curr_time;
      newinode->mtime_ns = 0;
      newinode->stime_s = curr_time;
      newinode->stime_ns = 0;
      newinode->size += totallen;
      writeblock(fs->fd, (unsigned char *)newinode, new_parent);

      res = findAndRemoveName(state, old_parent, old_name);
      if (res < 0) {
        fprintf(stderr,
                "ERROR rename() failed: old_name doesn't exist in old parent block");
        return res;
      }
      return 0;
    }
    
    extentsblocknum = extents->next;
  }

  if (slotfound == 0) {
    unsigned char superblock[BLOCK_SIZE];
    readblock(fs->fd, superblock, 0);
    struct Super *super = (struct Super *)superblock;
    
    if (super->free_head == 0) {
      fprintf(stderr, "ERROR rename() failed: no free blocks");
      return -ENOSPC;
    }
    
    uint32_t new_extent_num = super->free_head;
    unsigned char extent_block[BLOCK_SIZE];
    readblock(fs->fd, extent_block, new_extent_num);
    struct Free *free_extent = (struct Free *)extent_block;
    if (free_extent->type != 5) {
      fprintf(stderr, "ERROR rename() failed: free list corrupted");
      return -EIO;
    }
    
    super->free_head = free_extent->next;
    writeblock(fs->fd, superblock, 0);
    
    struct DirExtents *new_extent = (struct DirExtents *)extent_block;
    new_extent->type = 3;
    new_extent->next = 0;
    memset(new_extent->contents, 0, DIREXTENTS_DATA_SIZE);
    
    ret = insert_in_dir(new_extent->contents, DIREXTENTS_DATA_SIZE, totallen,
                        child, new_name, namelen);
    if (ret != 1) {
      fprintf(stderr, "ERROR rename() failed: couldn't insert in new extent");
      return -EIO;
    }
    
    writeblock(fs->fd, (unsigned char *)new_extent, new_extent_num);
    
    readblock(fs->fd, newblock, new_parent);
    newinode = (struct Inode *)newblock;
    if (newinode->next == 0) {
      newinode->next = new_extent_num;
    } else {
      uint32_t tail = newinode->next;
      unsigned char tail_block[BLOCK_SIZE];
      while (1) {
        readblock(fs->fd, tail_block, tail);
        struct DirExtents *tail_extent = (struct DirExtents *)tail_block;
        if (tail_extent->next == 0) {
          tail_extent->next = new_extent_num;
          writeblock(fs->fd, tail_block, tail);
          break;
        }
        tail = tail_extent->next;
      }
    }
    
    newinode->numblocks++;
    newinode->mtime_s = curr_time;
    newinode->mtime_ns = 0;
    newinode->stime_s = curr_time;
    newinode->stime_ns = 0;
    newinode->size += totallen;
    writeblock(fs->fd, (unsigned char *)newinode, new_parent);
  }

  res = findAndRemoveName(state, old_parent, old_name);
	if(res < 0){
		fprintf(stderr, "ERROR rename() failed: old_name doesn't exist in old parent block");
    return res;
  }

  return 0;
}

int addblock(void *state, uint32_t parentinode, uint32_t parent_block){
	arg_t *fs = (arg_t*)state;
  uint32_t curr_time = (uint32_t)time(NULL);
  unsigned char pblock[BLOCK_SIZE];
  unsigned char sblock[BLOCK_SIZE];
  unsigned char fblock[BLOCK_SIZE];
  unsigned char iblock[BLOCK_SIZE];
  readblock(fs->fd, pblock, parent_block);
  readblock(fs->fd, iblock, parentinode);
  readblock(fs->fd, sblock, 0);
	struct Super* super = (struct Super*)(sblock);
	if(super->type != 1){
    fprintf(stderr, "ERROR addblock() failed: super block corrupted");
    return -EIO;
  }
	if(super->free_head == 0){
    fprintf(stderr, "ERROR addblock() failed: no free blocks");
    return -ENOSPC;
  }
  uint32_t newbnum = super->free_head;
  readblock(fs->fd, fblock, newbnum);
	struct Free* free = (struct Free*)(fblock);
  super->free_head = free->next;
	writeblock(fs->fd, (unsigned char*)super, 0);
	struct FileExtents* newextent = (struct FileExtents*)(fblock);
  newextent->next = 0;
  newextent->type = 4;
  newextent->inode = parentinode;
	memset(newextent->contents, 0 , FILEEXTENTS_DATA_SIZE);
  writeblock(fs->fd, (unsigned char *)newextent, newbnum);

	if(parentinode == parent_block){
		struct Inode* inode = (struct Inode*)(iblock);
		if(inode->type != 2){
			fprintf(stderr, "ERROR addblock() failed: parent_block %u is not an inode and should be", parentinode);
      return -EINVAL;
    }
    inode->next = newbnum;
    inode->mtime_s = curr_time;
    inode->mtime_ns = 0;
    inode->stime_s = curr_time;
    inode->stime_ns = 0;
    inode->numblocks++;
		writeblock(fs->fd, (unsigned char*)inode, parentinode);
  } else {
		struct FileExtents* extents = (struct FileExtents*)(pblock);
		if(extents->type != 4){
			fprintf(stderr, "ERROR addblock() failed: parent_block %u is not an extents and should be", parent_block);
      return -EINVAL;
    }
		struct Inode* inode = (struct Inode*)(iblock);
		if(inode->type != 2){
			fprintf(stderr, "ERROR addblock() failed: parentinode %u is not an inode and should be", parentinode);
      return -EINVAL;
    }
    extents->next = newbnum;
    inode->mtime_s = curr_time;
    inode->mtime_ns = 0;
    inode->stime_s = curr_time;
    inode->stime_ns = 0;
    inode->numblocks++;
		writeblock(fs->fd, (unsigned char*)inode, parentinode);
		writeblock(fs->fd, (unsigned char*)extents, parent_block);
  }
  return 0;
}

int freeextents(void *state, uint32_t bnum){
	arg_t *fs = (arg_t*)state;
  unsigned char block[BLOCK_SIZE];
  readblock(fs->fd, block, bnum);
	struct FileExtents* extents = (struct FileExtents*)(block);
	if(extents->type != 4){
		fprintf(stderr, "ERROR freeextents() failed: block_num %u is not a File Extents", bnum);
    return -EINVAL;
  }
	if(extents->next != 0){
    int res = freeextents(state, extents->next);
		if(res < 0){
      return res;
    }
  }
  unsigned char sblock[BLOCK_SIZE];
  readblock(fs->fd, sblock, 0);
	struct Super* super = (struct Super*)(sblock);
	if(super->type != 1){
    fprintf(stderr, "ERROR freeextents() failed: super block corrupted");
    return -EIO;
  }
	struct Free* free = (struct Free*)(block);
  free->type = 5;
  free->next = super->free_head;
  super->free_head = bnum;
  writeblock(fs->fd, (unsigned char *)free, bnum);
	writeblock(fs->fd, (unsigned char *)super , 0);
  return 0;
}

int mytruncate(void *state, uint32_t block_num, off_t new_size){
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  readblock(fs->fd, block, block_num);
	struct Inode *inode = (struct Inode*)(block);
    if(inode->type != 2){
		fprintf(stderr, "ERROR truncate() failed: block_num %u is not an Inode, type= %u", block_num, inode->type);
    return -EINVAL;
  }
	if((inode->mode & S_IFMT) != S_IFREG){
		fprintf(stderr, "ERROR truncate() failed: block_num %u is not a FILE, mode= %u", block_num, inode->mode);
    return -ENOTDIR;
  }

  unsigned char superblock[BLOCK_SIZE];
  readblock(fs->fd, superblock, 0);
	struct Super *super = (struct Super*)(superblock);
	if(super->type != 1){
    fprintf(stderr, "ERROR truncate() failed: superblock corrupted");
    return -EIO;
  }
	if(new_size == inode->size){
		writeblock(fs->fd, (unsigned char*)inode, block_num);
    return 0;
  }
  int res;
	if(new_size < inode->size){
		if(new_size <= INODE_CONTENT_SIZE){
			if(inode->next != 0){
        res = freeextents(state, inode->next);
				if(res < 0){
          fprintf(stderr, "ERROR truncate() failed due to freeextents()");
          return res;
        }
        inode->next = 0;
        inode->numblocks = 1;
      }
    } else {
      int remainingsize = new_size - INODE_CONTENT_SIZE;
			int blocks_to_travel = (remainingsize + FILEEXTENTS_DATA_SIZE - 1) / FILEEXTENTS_DATA_SIZE;
      int blockskept = blocks_to_travel;
      unsigned char eblock[BLOCK_SIZE];
			struct FileExtents* extents = (struct FileExtents*)(eblock);
      uint32_t ebnum = inode->next;
      uint32_t prev = 0;
			while(blocks_to_travel != 0){
        readblock(fs->fd, eblock, ebnum);
        prev = ebnum;
        ebnum = extents->next;
        blocks_to_travel--;
      }
			if(extents->next != 0){
        uint32_t freestart = extents->next;
        extents->next = 0;
				writeblock(fs->fd, (unsigned char*)extents, prev);
        res = freeextents(state, freestart);
				if(res < 0){
          fprintf(stderr, "ERROR truncate() failed due to freeextents()");
          return res;
        }
      }
      inode->numblocks = 1 + blockskept;
    }
	} else if(new_size > inode->size){
    uint32_t blocks_needed = 1;
		if(new_size > INODE_CONTENT_SIZE){
      off_t extra = new_size - INODE_CONTENT_SIZE;
			blocks_needed += (extra + FILEEXTENTS_DATA_SIZE - 1) / FILEEXTENTS_DATA_SIZE;
    }
    uint32_t currentblocks = inode->numblocks;
		if(currentblocks == 0){
			//should never get here but sanity check
      currentblocks = 1;
    }
		if(blocks_needed > currentblocks){
      int to_add = blocks_needed - currentblocks;
      uint32_t tail;
      unsigned char eblock[BLOCK_SIZE];
      struct FileExtents *extents;
			extents = (struct FileExtents*)(eblock);
			while(to_add > 0){
				if(inode->next == 0){
          res = addblock(state, block_num, block_num);
					if(res < 0){
            fprintf(stderr, "ERROR truncate() failed due to addblock()");
            return res;
          }
        } else {
          tail = inode->next;
					while(1){
            readblock(fs->fd, eblock, tail);
						if(extents->type != 4){
							fprintf(stderr, "ERROR truncate() failed: %u is not a File Extents", tail);
              return -EINVAL;
            }
						if(extents->next == 0){
              break;
            }
            tail = extents->next;
          }
          res = addblock(state, block_num, tail);
					if(res < 0){
            fprintf(stderr, "ERROR truncate() failed due to addblock()");
            return res;
          }
        }
        readblock(fs->fd, block, block_num);
				inode = (struct Inode*)block;
        to_add--;
      }
    }
  }
  inode->size = new_size;
  uint32_t curr_time = (uint32_t)time(NULL);
  inode->mtime_s = curr_time;
  inode->mtime_ns = 0;
  inode->stime_s = curr_time;
  inode->stime_ns = 0;
	writeblock(fs->fd, (unsigned char*)inode, block_num);
  return 0;
}

static int write_file(void *state, uint32_t block_num, const char *buff, size_t wr_len, off_t wr_offset){
  arg_t *fs = (arg_t *)state;
  unsigned char block[BLOCK_SIZE];
  size_t bytes_written = 0;
  off_t current_offset = wr_offset;
  int is_first_block = 1;
  unsigned char current_block[BLOCK_SIZE];
  uint32_t current_block_num = block_num;
  uint64_t new_size;
  uint64_t blocks_needed;
  uint64_t i;

  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);

  struct Inode *inode = (struct Inode *)block;

  // make sure its a regular inode
    if (inode->type != TYPE_INODE){
    return -ENOENT;
  }
    if(!S_ISREG(inode->mode)) {
    return -EISDIR;
  }

  new_size = wr_offset + wr_len;

  // check if we need to expand the file
    if (new_size > inode->size){
    if (new_size <= INODE_CONTENT_SIZE) {
      blocks_needed = 1;
        }
        else {
            blocks_needed = 1 + ((new_size - INODE_CONTENT_SIZE + FILEEXTENTS_DATA_SIZE - 1) / FILEEXTENTS_DATA_SIZE);
    }

        if (blocks_needed > inode->numblocks){
      unsigned char superblock[BLOCK_SIZE];
      readblock(fs->fd, superblock, 0);
      struct Super *super = (struct Super *)superblock;
      uint32_t allocated_blocks[256];
      int num_allocated = 0;
      for (i = inode->numblocks; i < blocks_needed; i++) {
        if (super->free_head == 0) {
          //rollback
          readblock(fs->fd, superblock, 0);
          super = (struct Super *)superblock;
          int j;
          for (j = num_allocated - 1; j >= 0; j--) {
            unsigned char free_blk[BLOCK_SIZE];
            readblock(fs->fd, free_blk, allocated_blocks[j]);
            struct Free *f = (struct Free *)free_blk;
            f->type = TYPE_FREE;
            f->next = super->free_head;
            super->free_head = allocated_blocks[j];
            writeblock(fs->fd, free_blk, allocated_blocks[j]);
            writeblock(fs->fd, superblock, 0);
            readblock(fs->fd, superblock, 0);
            super = (struct Super *)superblock;
          }
          return -ENOSPC;
        }

        uint32_t new_block_num = super->free_head;
        allocated_blocks[num_allocated++] = new_block_num;
        //remove from free list
        unsigned char new_block[BLOCK_SIZE];
        readblock(fs->fd, new_block, new_block_num);
        struct Free *free_block = (struct Free *)new_block;
        super->free_head = free_block->next;
        writeblock(fs->fd, superblock, 0);

        struct FileExtents *new_extent = (struct FileExtents *)new_block;
        new_extent->type = TYPE_FILE_EXTENT;
        new_extent->inode = block_num;
        new_extent->next = 0;
        memset(new_extent->contents, 0, FILEEXTENTS_DATA_SIZE);
        writeblock(fs->fd, new_block, new_block_num);
      }

      //all blocks allocated successfully, so we can now link them
      uint32_t last_block = block_num;
      uint32_t cur = inode->next;
      while (cur != 0) {
        last_block = cur;
        unsigned char temp_block[BLOCK_SIZE];
        readblock(fs->fd, temp_block, cur);
        struct FileExtents *extent = (struct FileExtents *)temp_block;
        cur = extent->next;
      }
      
      int j;
      for (j = 0; j < num_allocated; j++) {
        uint32_t new_block_num = allocated_blocks[j];
        
        if (last_block == block_num) {
          unsigned char iblock[BLOCK_SIZE];
          readblock(fs->fd, iblock, block_num);
          struct Inode *inode_ptr = (struct Inode *)iblock;
          inode_ptr->next = new_block_num;
          writeblock(fs->fd, iblock, block_num);
        } else {
          unsigned char temp_block[BLOCK_SIZE];
          readblock(fs->fd, temp_block, last_block);
          struct FileExtents *extent = (struct FileExtents *)temp_block;
          extent->next = new_block_num;
          writeblock(fs->fd, temp_block, last_block);
        }
        
        last_block = new_block_num;
      }
    }

    // update inode size and numblocks
    memset(block, 0, BLOCK_SIZE);
    readblock(fs->fd, block, block_num);
    inode = (struct Inode *)block;
    inode->size = new_size;
    inode->numblocks = blocks_needed;
    writeblock(fs->fd, (unsigned char *)inode, block_num);
  }

  // reload inode
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);
  inode = (struct Inode *)block;

  memcpy(current_block, block, BLOCK_SIZE);

  // skip to the correct block based on offset
  if (current_offset >= INODE_CONTENT_SIZE) {
    current_offset -= INODE_CONTENT_SIZE;
    current_block_num = inode->next;

    // skip through extent blocks
        while(current_block_num != 0 && current_offset >= FILEEXTENTS_DATA_SIZE) {
      current_offset -= FILEEXTENTS_DATA_SIZE;
      memset(current_block, 0, BLOCK_SIZE);
      readblock(fs->fd, current_block, current_block_num);
      struct FileExtents *extent = (struct FileExtents *)current_block;
      current_block_num = extent->next;
    }

    if (current_block_num != 0) {
      memset(current_block, 0, BLOCK_SIZE);
      readblock(fs->fd, current_block, current_block_num);
      is_first_block = 0;
    }
  }

  // write data across blocks
    while(bytes_written < wr_len) {
    int content_start;
    int content_size;

        if(is_first_block) {
      content_start = 64;
      content_size = INODE_CONTENT_SIZE;
        }
        else {
      content_start = 8;
      content_size = FILEEXTENTS_DATA_SIZE;
    }

    int available = content_size - current_offset;
    int to_write;
    if (wr_len - bytes_written < available) {
      to_write = wr_len - bytes_written;
        }
        else {
      to_write = available;
    }

    // copy data into block
        memcpy(current_block + content_start + current_offset, buff + bytes_written, to_write);

    // write block back to disk
    writeblock(fs->fd, current_block, current_block_num);

    bytes_written += to_write;
    current_offset = 0;

    // move to next block if needed
    if (bytes_written < wr_len) {
      if (is_first_block) {
        current_block_num = inode->next;
            }
            else {
        struct FileExtents *extent = (struct FileExtents *)current_block;
        current_block_num = extent->next;
      }

      if (current_block_num == 0) {
        break; // shouldn't happen
      }

      memset(current_block, 0, BLOCK_SIZE);
      readblock(fs->fd, current_block, current_block_num);
      is_first_block = 0;
    }
  }

  // update inode time
  memset(block, 0, BLOCK_SIZE);
  readblock(fs->fd, block, block_num);
  inode = (struct Inode *)block;

  uint32_t cur_time = (uint32_t)time(NULL);
  inode->mtime_s = cur_time;
  inode->mtime_ns = 0;
  inode->stime_s = cur_time;
  inode->stime_ns = 0;

  writeblock(fs->fd, (unsigned char *)inode, block_num);

  return bytes_written;
}
struct cpe453fs_ops *CPE453_get_operations(void) {
  static struct cpe453fs_ops ops;
  static arg_t args;
  memset(&ops, 0, sizeof(ops));
  memset(&args, 0, sizeof(args));

  ops.arg = &args;
  ops.set_file_descriptor = set_file_descriptor;
  ops.root_node = root_node;
  ops.getattr = getattr;
  ops.readdir = readdir;
  ops.open = open_file;
  ops.read = read_file;
  ops.readlink = readlink_file;
    //read/write
  ops.chmod = chmod_file;
  ops.chown = chown_file;
  ops.utimens= utimens;
  ops.rmdir = rmdir_dir;
  ops.unlink = unlink_file;
  ops.mknod = mknod_file;
  ops.symlink = symlink_file;
  ops.mkdir = mkdir_file;
  ops.link = mylink;
  ops.rename = myrename;
  ops.truncate = mytruncate;
  ops.write = write_file;
  return &ops;
}
