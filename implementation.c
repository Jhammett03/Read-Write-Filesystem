#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include "cpe453fs.h"

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

static uint32_t read_uint32(unsigned char *buf, int offset) {
    return *((uint32_t *)(buf + offset));
}

static uint16_t read_uint16(unsigned char *buf, int offset) {
    return *((uint16_t *)(buf + offset));
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
    uint32_t type = read_uint32(block, 0);
    if (type != TYPE_INODE) {
        return -ENOTDIR;
    }
    uint32_t mode = read_uint32(block, 4);
    if (!S_ISDIR(mode)){
        return -ENOTDIR;
    }

    //find directory entry
    uint32_t target_inode = 0;
    int found_offset = -1;
    uint16_t found_len = 0;
    int offset = 64;

    //check all names
    while (offset + 6 < 4092){
        uint16_t entry_len = read_uint16(block, offset);
        if (entry_len == 0) break;
        uint32_t entry_inode = read_uint32(block, offset + 2);
        int name_len = entry_len - 6;
        if (strncmp((char *)(block + offset + 6), name, name_len) == 0 && name[name_len] == '\0') {
            target_inode = entry_inode;
            found_offset = offset;
            found_len = entry_len;
            break;
        }
        offset += entry_len;
    }

    if (target_inode == 0){
        return -ENOENT; //not found
    }

    //read the directory's inode
    unsigned char target_block[BLOCK_SIZE];
    memset(target_block, 0, BLOCK_SIZE);
    readblock(fs->fd, target_block, target_inode);

    //make sure its a directory
    uint32_t target_type = read_uint32(target_block, 0);
    if (target_type != TYPE_INODE) {
        return -ENOENT;
    }
    uint32_t target_mode = read_uint32(target_block, 4);
    if (!S_ISDIR(target_mode)) {
        return -ENOTDIR;
    }

    //empty check
    int check_offset = 64;
    while (check_offset + 6 < 4092){
        uint16_t entry_len = read_uint16(target_block, check_offset);
        if (entry_len == 0) {
            break;
        }
        return -ENOTEMPTY;
    }
    //make sure there are no extent blocks
    uint32_t target_next = read_uint32(target_block, 4092);
    if (target_next != 0) {
        return -ENOTEMPTY;
    }

    //free inode
    *((uint32_t *)target_block) = TYPE_FREE;
    writeblock(fs->fd, target_block, target_inode);

    //remove from parent dir
    memset(block, 0, BLOCK_SIZE);
    readblock(fs->fd, block, block_num);
    memset(block + found_offset, 0, found_len);
    writeblock(fs->fd, block, block_num);

    return 0;
}

static int unlink_file(void *state, uint32_t block_num, const char *name){
    arg_t *fs = (arg_t *)state;
    unsigned char block[BLOCK_SIZE];
    memset(block, 0, BLOCK_SIZE);
    readblock(fs->fd, block, block_num);

    //parent must be directory inode
    uint32_t type = read_uint32(block, 0);
    if (type != TYPE_INODE){
        return -ENOTDIR;
    }
    uint32_t mode = read_uint32(block, 4);
    if (!S_ISDIR(mode)){
        return -ENOTDIR;
    }

    //find file entry in parent dir
    uint32_t target_inode = 0;
    int found_offset = -1;
    uint16_t found_len = 0;
    int offset = 64;

    while (offset + 6 < 4092){
        uint16_t entry_len = read_uint16(block, offset);
        if (entry_len == 0) break;
        uint32_t entry_inode = read_uint32(block, offset + 2);
        int name_len = entry_len - 6;

        if (strncmp((char *)(block + offset + 6),name, name_len) == 0 && name[name_len] == '\0') {
            target_inode = entry_inode;
            found_offset = offset;
            found_len = entry_len;
            break;
        }
        offset += entry_len;
    }
    
    if (target_inode == 0) {
        return -ENOENT; // not found
    }


    //read file's inode
    unsigned char target_block[BLOCK_SIZE];
    memset(target_block, 0, BLOCK_SIZE);
    readblock(fs->fd, target_block, target_inode);

    //make sure its an inode
    uint32_t target_type = read_uint32(target_block, 0);
    if (target_type != TYPE_INODE) {
        return -ENOENT;
    }
    uint32_t target_mode = read_uint32(target_block, 4);
    if (S_ISDIR(target_mode)) {
        return -EISDIR;
    }

    //find link count
    uint16_t nlinks = read_uint16(target_block, 6);
    //decrement links
    nlinks--;
    *((uint16_t *)(target_block + 6)) = nlinks;

    //if nlinks == 0 free inode and extents
    if (nlinks == 0){
        uint32_t next_extent = read_uint32(target_block, 4092);
        while (next_extent != 0){
            unsigned char extent_block[BLOCK_SIZE];
            memset(extent_block, 0, BLOCK_SIZE);
            readblock(fs->fd, extent_block, next_extent);
            uint32_t next = read_uint32(extent_block, 4092);

            //mark extent as free
            *((uint32_t *)extent_block) = TYPE_FREE;
            writeblock(fs->fd, extent_block, next_extent);
            next_extent = next;
        }
        //mark inode as free
        *((uint32_t *)target_block) = TYPE_FREE;
    }

    writeblock(fs->fd, target_block, target_inode);

    //remove from parent dir
    memset(block, 0, BLOCK_SIZE);
    readblock(fs->fd, block, block_num);
    memset(block + found_offset, 0, found_len);
    writeblock(fs->fd, block, block_num);

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
    uint32_t total_blocks = read_uint32(superblock, 4084);

    uint32_t free_inode = 0;
    uint32_t i;
    for (i = 1; i < total_blocks; i++) {
        unsigned char test_block[BLOCK_SIZE];
        memset(test_block, 0, BLOCK_SIZE);
        readblock(fs->fd, test_block, i);
        uint32_t block_type = read_uint32(test_block, 0);
        if (block_type == TYPE_FREE) {
            free_inode = i;
            break;
        }
    }
    if (free_inode == 0) {
        return -ENOSPC; //no space
    }
    //make the new inode
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
    *((uint32_t *)(new_inode + 24)) = cur_time; //atime secs
    *((uint32_t *)(new_inode + 28)) = 0; //nsecs
    *((uint32_t *)(new_inode + 32)) = cur_time; //mtime secs
    *((uint32_t *)(new_inode + 36)) = 0; //nsecs
    *((uint32_t *)(new_inode + 40)) = cur_time; //ctime secs
    *((uint32_t *)(new_inode + 44)) = 0; //nsecs
    *((uint32_t *)(new_inode + 48)) = 0; //size = 0
    *((uint32_t *)(new_inode + 52)) = 0; //blocks
    *((uint32_t *)(new_inode + 4092)) = 0; //next extent = NULL

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
        // No space in parent inode
        *((uint32_t *)(new_inode)) = TYPE_FREE;
        writeblock(fs->fd, new_inode, free_inode);
        return -ENOSPC;
    }
    writeblock(fs->fd, block, parent_block);
    return 0;
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
    ops.utimens = utimens;
    ops.rmdir = rmdir_dir;
    ops.unlink = unlink_file;
    ops.mknod = mknod_file;

    return &ops;
}
