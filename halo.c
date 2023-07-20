#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <stddef.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/mman.h>


#include "ext4.h"

int fd;
size_t raw_len;
char *raw;

struct ext4_super_block *sb;
char (*descs)[EXT4_DESC_SIZE];

size_t block_size;
size_t blocks_per_group;
size_t inodes_per_group;
size_t inode_size;
size_t bg_size;
size_t bg_nr;

size_t cwd_inode = 2 /* root directory */;

struct ext4_super_block *
get_sb() {
    return (struct ext4_super_block *)(raw + 1024);
}

struct ext4_group_desc *
get_desc(size_t bg_i) {
    assert(bg_i < bg_nr);
    return (struct ext4_group_desc *)(descs[bg_i]);
}

struct ext4_inode *
get_inode(size_t inode_num) {
    assert(0 < inode_num);
    assert(inode_num < sb->s_inodes_count);
    size_t bg = (inode_num - 1) / inodes_per_group;
    size_t index = (inode_num - 1) % inodes_per_group;
    struct ext4_group_desc *desc = get_desc(bg);
    char *inodes = raw + desc->bg_inode_table_lo * block_size;
    return (struct ext4_inode *)(inodes + index * inode_size);
}

void
clear(char *bitmap, size_t loc) {
    bitmap[loc / 8] &= ~(1 << (loc % 8));
}

void
set(char *bitmap, size_t loc) {
    bitmap[loc / 8] |= (1 << (loc % 8));
}

int
is_hit(char *bitmap, size_t loc) {
    return !!(bitmap[loc / 8] & (1 << (loc % 8)));
}

void
update_all_redundant_metadata() {
    for (size_t bg = 1; bg < bg_nr; bg++) {
	struct ext4_super_block *bg_sb = (struct ext4_super_block *)(raw + bg * bg_size);
	memcpy(bg_sb, sb, sizeof(*sb));
	bg_sb->s_block_group_nr = bg;

	char *bg_desc = raw + bg * bg_size + 4096;
	memcpy(bg_desc, descs, bg_nr * EXT4_DESC_SIZE);
    }
}

size_t
alloc_block() {
    for (size_t bg = 0; bg < bg_nr; bg++) {
	struct ext4_group_desc *desc = get_desc(bg);
	char *block_bitmap = raw + desc->bg_block_bitmap_lo * block_size;
	for (size_t block_ofst_in_bg = 0;
	     block_ofst_in_bg < blocks_per_group;
	     block_ofst_in_bg++) {
	    if (!is_hit(block_bitmap, block_ofst_in_bg)) {
		size_t block = bg * blocks_per_group + block_ofst_in_bg;
		set(block_bitmap, block_ofst_in_bg);
		sb->s_free_blocks_count_lo--;
		desc->bg_free_blocks_count_lo--;
		update_all_redundant_metadata();
		memset(raw + block * block_size, 0, block_size);
		return block;
	    }
	}
    }
    assert(0);
    return 0;
}

void
free_block(size_t block_num) {
    if (block_num == 0)
	return;
    memset(raw + block_num * block_size, 0, block_size);
    size_t bg = block_num / blocks_per_group;
    size_t block_ofst_in_bg = block_num % blocks_per_group;

    struct ext4_group_desc *desc = get_desc(bg);
    char *block_bitmap = raw + desc->bg_block_bitmap_lo * block_size;

    assert(is_hit(block_bitmap, block_ofst_in_bg));

    clear(block_bitmap, block_ofst_in_bg);
    sb->s_free_blocks_count_lo++;
    desc->bg_free_blocks_count_lo++;
    update_all_redundant_metadata();
}

size_t
alloc_inode() {
    for (size_t bg = 0; bg < bg_nr; bg++) {
	struct ext4_group_desc *desc = get_desc(bg);
	char *inode_bitmap = raw + desc->bg_inode_bitmap_lo * block_size;
	for (size_t inode_table_ofst = 0;
	     inode_table_ofst < inodes_per_group;
	     inode_table_ofst++) {
	    if (!is_hit(inode_bitmap, inode_table_ofst)) {
		size_t inode_num = bg * inodes_per_group + inode_table_ofst;
		if (inode_num < 12)
		  continue;
		set(inode_bitmap, inode_table_ofst);
		sb->s_free_inodes_count--;
		desc->bg_free_inodes_count_lo--;
		update_all_redundant_metadata();
		memset(get_inode(inode_num), 0, inode_size);
		return inode_num;
	    }
	}
    }
    assert(0);
    return 0;
}

void
free_inode(size_t inode_num) {
    assert(11 < inode_num);
    struct ext4_inode *inode = get_inode(inode_num);
    assert(inode->i_links_count == 0);
    assert(inode->i_size_lo <= 12 * block_size);
    for (int i = 0; i < 12; i++)
      free_block(inode->i_block[i]);

    size_t bg = inode_num / inodes_per_group;
    size_t inode_table_ofst = inode_num % inodes_per_group;

    struct ext4_group_desc *desc = get_desc(bg);
    char *inode_bitmap = raw + desc->bg_inode_bitmap_lo * block_size;

    assert(is_hit(inode_bitmap, inode_table_ofst));

    clear(inode_bitmap, inode_table_ofst);
    sb->s_free_inodes_count++;
    desc->bg_free_inodes_count_lo++;
    update_all_redundant_metadata();
}

char *
logical_addr_to_raw(struct ext4_inode *inode, size_t logic_addr) {
    assert(logic_addr < inode->i_size_lo);
    size_t logic_block_i = logic_addr / block_size;
    assert(logic_block_i < 12);

    size_t block_num = inode->i_block[logic_block_i];
    size_t block_ofst = logic_addr % block_size;

    assert(block_num != 0);

    return raw + block_num * block_size + block_ofst;
}

void
fetch_4_bytes(struct ext4_inode *inode,
	      size_t logic_addr, uint32_t *buf) {
    assert(logic_addr % 4 == 0);
    *buf = *(uint32_t *)logical_addr_to_raw(inode, logic_addr);
}

int
foreach_directory_entries(size_t inode_num,
			  int f(struct ext4_inode *dir_inode,
				size_t logic_addr_of_dentry,
				uint32_t inode,
				uint8_t file_type,
				uint8_t name_len,
				const char *name,
				void *context),
			  void *context) {
    struct ext4_inode *dir_inode = get_inode(inode_num);
    assert(S_ISDIR(dir_inode->i_mode));
    assert(dir_inode->i_size_lo % 4096 == 0); /* page aligned for simplicity */

    size_t logic_addr = 0;
    while (logic_addr < dir_inode->i_size_lo) {
	static struct ext4_dir_entry_2 t;
	fetch_4_bytes(dir_inode,
		      logic_addr + offsetof(struct ext4_dir_entry_2, inode),
		      (uint32_t *)&t.inode);
	fetch_4_bytes(dir_inode,
		      logic_addr + offsetof(struct ext4_dir_entry_2, rec_len),
		      (uint32_t *)&t.rec_len);
	size_t this_entry_size = t.rec_len;

	if (t.inode != 0) {
	    for (int i = 0; i < this_entry_size && i < sizeof(t); i += 4) {
		fetch_4_bytes(dir_inode, logic_addr + i, (uint32_t *)((char *)&t + i));
	    }

	    int file_type = t.file_type;
	    if (file_type == EXT4_FT_UNKNOWN) {
		struct ext4_inode *inode = get_inode(t.inode);
		file_type = ext4_type_by_mode[inode->i_mode >> S_SHIFT];
	    }

	    int ret = f(dir_inode, logic_addr, t.inode,
			file_type, t.name_len, t.name, context);
	    if (ret < 0)
	      return ret;
	}

	logic_addr += this_entry_size;
    }
    return 0;
}

void
add_directory_entry(size_t dir_inode_num, size_t inode, const char *name) {
    struct ext4_inode *dir_inode = get_inode(dir_inode_num);
    assert(S_ISDIR(dir_inode->i_mode));
    assert(dir_inode->i_size_lo % 4096 == 0); /* page aligned for simplicity */

    size_t total_block = dir_inode->i_size_lo / block_size;
    assert(total_block < 11);

    size_t new_block = alloc_block();
    dir_inode->i_block[total_block] = new_block;
    dir_inode->i_size_lo += block_size;
    dir_inode->i_blocks_lo += block_size / 512;

    struct ext4_dir_entry_2 *dentry = (struct ext4_dir_entry_2 *)(raw + new_block * block_size);
    dentry->inode = inode;
    dentry->rec_len = block_size;
    dentry->name_len = strlen(name);
    strncpy(dentry->name, name, dentry->name_len);
}

int
delete_directory_entry_1(struct ext4_inode *dir_inode,
			 size_t logic_addr_of_dentry,
			 uint32_t inode_1,
			 uint8_t file_type,
			 uint8_t name_len,
			 const char *name,
			 void *context) {
    if (strcmp(name, (const char *)context) == 0) {
	*(uint32_t *)logical_addr_to_raw(dir_inode,
					 logic_addr_of_dentry) = 0;
	return -1;
    }
    return 0;
}

void
delete_directory_entry(size_t dir_inode_num, const char *name) {
    foreach_directory_entries(dir_inode_num, delete_directory_entry_1,
			      (void *)name);
}

void
open_raw(const char *path) {
    fd = open(path, O_RDWR);
    assert(0 <= fd);

    raw_len = lseek(fd, 0, SEEK_END);
    assert(0 <= raw_len);

    assert(4096 <= raw_len);

    raw = mmap(NULL, raw_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(raw != MAP_FAILED);

    sb = get_sb();
    descs = (char (*) [32])(raw + 4096);

    block_size = 1 << (10 + sb->s_log_block_size);
    assert(block_size == 4096);

    blocks_per_group = sb->s_blocks_per_group;
    inodes_per_group = sb->s_inodes_per_group;
    inode_size = sb->s_inode_size;

    assert(sb->s_magic == 0xef53);
    assert(sb->s_state == EXT4_VALID_FS);
    assert(sb->s_feature_compat == 0);
    assert(sb->s_feature_ro_compat == 0);

    bg_size = sb->s_blocks_per_group * block_size;
    bg_nr = raw_len / bg_size;
}

int
ls_1(struct ext4_inode *dir_inode,
     size_t logic_addr_of_dentry,
     uint32_t inode,
     uint8_t file_type,
     uint8_t name_len,
     const char *name,
     void *context) {
    printf("%.*s\n", name_len, name);
    return 0;
}

void
ls() {
    puts("> ls");
    foreach_directory_entries(cwd_inode, ls_1, NULL);
}

int
ls_l_1(struct ext4_inode *dir_inode,
       size_t logic_addr_of_dentry,
       uint32_t inode_1,
       uint8_t file_type,
       uint8_t name_len,
       const char *name,
       void *context) {
    struct ext4_inode *inode = get_inode(inode_1);
    switch (file_type) {
      case EXT4_FT_REG_FILE: putchar('-'); break;
      case EXT4_FT_DIR: putchar('d'); break;
      case EXT4_FT_SYMLINK: putchar('l'); break;
      case EXT4_FT_FIFO: putchar('p'); break;
      case EXT4_FT_BLKDEV: putchar('b'); break;
      case EXT4_FT_CHRDEV: putchar('c'); break;
      case EXT4_FT_SOCK: putchar('s'); break;
    }

    putchar(inode->i_mode & S_IRUSR ? 'r' : '-');
    putchar(inode->i_mode & S_IWUSR ? 'w' : '-');
    putchar(inode->i_mode & S_IXUSR ? 'x' : '-');
    putchar(inode->i_mode & S_IRGRP ? 'r' : '-');
    putchar(inode->i_mode & S_IWGRP ? 'w' : '-');
    putchar(inode->i_mode & S_IXGRP ? 'x' : '-');
    putchar(inode->i_mode & S_IROTH ? 'r' : '-');
    putchar(inode->i_mode & S_IWOTH ? 'w' : '-');
    putchar(inode->i_mode & S_IXOTH ? 'x' : '-');

    putchar('\t');

    printf("%d\t", (int)inode->i_links_count);
    printf("%d\t", (int)inode->i_uid);
    printf("%d\t", (int)inode->i_gid);
    printf("%d\t", (int)inode->i_size_lo);
    printf("%d\t", (int)inode->i_mtime);

    printf("%.*s\n", name_len, name);
    return 0;
}

void
ls_l() {
    puts("> ls -l");
    foreach_directory_entries(cwd_inode, ls_l_1, NULL);
}

struct find_by_name_2 {
    const char *name;
    size_t inode;
};

int
find_by_name_1(struct ext4_inode *dir_inode,
	       size_t logic_addr_of_dentry,
	       uint32_t inode_1,
	       uint8_t file_type,
	       uint8_t name_len,
	       const char *name,
	       void *context) {
    struct find_by_name_2 *t = (struct find_by_name_2 *)context;
    if (strcmp(name, t->name) == 0) {
	t->inode = inode_1;
	return -1;
    }
    return 0;
}

size_t
find_by_name(const char *name) {
    struct find_by_name_2 t = { .name = name, .inode = 0 };
    foreach_directory_entries(cwd_inode, find_by_name_1, (void *)&t);
    return t.inode;
}

void
cd(const char *name) {
    printf("> cd %s\n", name);
    size_t inode_num = find_by_name(name);
    if (inode_num == 0) {
	printf("%s not found.\n", name);
	return;
    }
    struct ext4_inode *inode = get_inode(inode_num);
    if (!S_ISDIR(inode->i_mode)) {
	printf("%s is not dir\n", name);
	return;
    }
    cwd_inode = inode_num;
}

void
touch(const char *name) {
    printf("> touch %s\n", name);
    if (find_by_name(name) != 0) {
	printf("%s already exists.\n", name);
	return;
    }
    size_t new_inode = alloc_inode();
    struct ext4_inode *inode = get_inode(new_inode);
    inode->i_mode = S_IFREG | S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH;
    inode->i_links_count = 1;

    add_directory_entry(cwd_inode, new_inode, name);
}

void
my_mkdir(const char *name) {
    printf("> mkdir %s\n", name);
    if (find_by_name(name) != 0) {
	printf("%s already exists.\n", name);
	return;
    }
    size_t new_inode = alloc_inode();
    struct ext4_inode *inode = get_inode(new_inode);
    struct ext4_inode *inode_of_cwd = get_inode(cwd_inode);

    inode->i_mode = S_IFDIR | S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH;
    inode->i_size_lo = 4096;
    inode->i_links_count = 2;
    inode->i_blocks_lo = inode->i_size_lo / 512;
    inode->i_block[0] = alloc_block();

    char *raw_block = raw + inode->i_block[0] * block_size;

    ((struct ext4_dir_entry_2 *)raw_block)->inode = new_inode;
    ((struct ext4_dir_entry_2 *)raw_block)->rec_len = 12;
    ((struct ext4_dir_entry_2 *)raw_block)->name_len = 1;
    ((struct ext4_dir_entry_2 *)raw_block)->file_type = 0;
    ((struct ext4_dir_entry_2 *)raw_block)->name[0] = '.';
    ((struct ext4_dir_entry_2 *)raw_block)->name[1] = '\0';

    ((struct ext4_dir_entry_2 *)(raw_block + 12))->inode = cwd_inode;
    ((struct ext4_dir_entry_2 *)(raw_block + 12))->rec_len = 4096 - 12;
    ((struct ext4_dir_entry_2 *)(raw_block + 12))->name_len = 2;
    ((struct ext4_dir_entry_2 *)(raw_block + 12))->file_type = 0;
    ((struct ext4_dir_entry_2 *)(raw_block + 12))->name[0] = '.';
    ((struct ext4_dir_entry_2 *)(raw_block + 12))->name[1] = '.';
    ((struct ext4_dir_entry_2 *)(raw_block + 12))->name[2] = '\0';

    add_directory_entry(cwd_inode, new_inode, name);
    inode_of_cwd->i_links_count++;
}

int
my_rmdir_1(struct ext4_inode *dir_inode,
	   size_t logic_addr_of_dentry,
	   uint32_t inode_1,
	   uint8_t file_type,
	   uint8_t name_len,
	   const char *name,
	   void *context) {
    (*(size_t *)context)++;
    return 0;
}

int
my_rmdir_2(struct ext4_inode *dir_inode,
	   size_t logic_addr_of_dentry,
	   uint32_t inode_1,
	   uint8_t file_type,
	   uint8_t name_len,
	   const char *name,
	   void *context) {
    if (strcmp(name, (const char *)context) == 0) {
	*(uint32_t *)logical_addr_to_raw(get_inode(cwd_inode),
					 logic_addr_of_dentry) = 0;
	return -1;
    }
    return 0;
}

void
my_rmdir(const char *name) {
    printf("> rmdir %s\n", name);
    size_t inode_num = find_by_name(name);
    if (inode_num == 0) {
	printf("%s not fount\n", name);
	return;
    }
    struct ext4_inode *inode = get_inode(inode_num);
    if (!S_ISDIR(inode->i_mode)) {
	printf("%s is not dir\n", name);
	return;
    }

    size_t dentry_nr = 0;
    foreach_directory_entries(inode_num, my_rmdir_1, (void *)&dentry_nr);
    if (dentry_nr != 2) {
	printf("dir %s has content\n", name);
	return;
    }

    delete_directory_entry(cwd_inode, name);
    inode->i_links_count = 0;
    free_inode(inode_num);
}

void
mv(const char *src, const char *dst) {
    printf("> mv %s %s\n", src, dst);
    size_t inode = find_by_name(src);
    if (inode == 0) {
	printf("%s not found.\n", src);
	return;
    }
    if (find_by_name(dst) != 0) {
	printf("%s already exists.\n", dst);
	return;
    }
    delete_directory_entry(cwd_inode, src);
    add_directory_entry(cwd_inode, inode, dst);
}

void
my_chmod(uint16_t mode, const char *name) {
    printf("> chmod 0%o %s\n", (int)mode, name);
    size_t inode_num = find_by_name(name);
    if (inode_num == 0) {
	printf("%s not fount\n", name);
	return;
    }
    struct ext4_inode *inode = get_inode(inode_num);
    inode->i_mode = (inode->i_mode & ~0777) | (mode & 0777);
}

int
main(int argc, char *argv[]) {
    assert(argc == 2);
    printf("Open ext4 img: %s\n", argv[1]);

    open_raw(argv[1]);

    ls();
    cd("1");
    ls_l();
    touch("2");
    touch("new_file");
    ls_l();
    my_mkdir("new_dir1");
    my_mkdir("new_dir2");
    ls_l();
    my_rmdir("new_dir1");
    my_rmdir("new_file");
    my_rmdir("2");
    ls_l();
    mv("new_file", "new_file2");
    mv("new_dir2", "new_dir3");
    ls_l();
    my_chmod(0777, "new_dir3");
    my_chmod(0655, "new_file2");
    ls_l();

    return 0;
}

