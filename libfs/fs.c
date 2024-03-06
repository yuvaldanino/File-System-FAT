#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define SIGNATURE "ECS150FS"
#define SIGNATURE_LENGTH 8
#define ROOT_PADDING 10
#define SUPERBLOCK_PADDING 4079
#define MAX_ROOT_ENTRIES 128

typedef struct __attribute__((packed)) {
	uint8_t signature[SIGNATURE_LENGTH];
	uint16_t root_block_index;
	uint16_t data_block_index;
	uint16_t data_block_amount;
	uint8_t fat_block_amount;
	uint16_t total_block_amount;
	uint8_t padding[SUPERBLOCK_PADDING];
} SuperBlock;

typedef struct __attribute__((packed)) {
	uint16_t entries[BLOCK_SIZE / 2];
} FATEntry;

typedef struct __attribute__((packed)) {

	uint8_t file_name[FS_FILENAME_LEN];
	uint32_t file_size;
	uint16_t first_data_block_index;
	uint8_t padding[ROOT_PADDING];
} RootEntry;

typedef struct __attribute__((packed)) {
	uint8_t file_name[FS_FILENAME_LEN];
	uint8_t offset;
	uint8_t index;
} FileDescriptor;

typedef struct __attribute__((packed)) {
	SuperBlock *super_block;
	FATEntry *fat_entry;
	RootEntry root_directory[FS_FILE_MAX_COUNT];
} FileSystem;

static SuperBlock *super_block;
static FATEntry *fat_entry = NULL;
static RootEntry root_directory[FS_FILE_MAX_COUNT];
static FileDescriptor *file_descriptors[FS_OPEN_MAX_COUNT];
static FileSystem *file_system;

int fs_mount(const char *diskname)
{
	// Open virtual disk
	if (block_disk_open(diskname) != 0) {
		return -1;
	}
	// Read super_block at beginning of virtual disk
	super_block = malloc(sizeof(SuperBlock));
	if (block_read(0, super_block) != 0) {
		return -1;
	}
	// Verify signature has correct signature
	if (memcmp(super_block->signature, SIGNATURE, SIGNATURE_LENGTH) != 0) {
		return -1;
	}

	// Verify super_block has correct block amount
	if (super_block->total_block_amount != block_disk_count()) {
		return -1;
	}
	printf("made it past initial checks");

	// Read blocks into a FAT array
	fat_entry = malloc(sizeof(FATEntry) * super_block->fat_block_amount);
	for (int i = 0; i < super_block->fat_block_amount; i++) {
		if (block_read(i+1, fat_entry+i) != 0) {
			return -1;
		}
	}

	// Read blocks into a root directory array
	if (block_read(super_block->root_block_index, &root_directory) != 0) {
		return -1;
	}

	return 0;
}

int fs_umount(void)
{
	if (block_disk_close() != 0) {
		return -1;
	}

	memset(&super_block, 0, sizeof(SuperBlock));
	memset(&root_directory, 0, sizeof(RootEntry));
	free(fat_entry);

	return 0;
}

int fs_info(void)
{
	int free_fat_blocks = 0;
	int free_root_entries = 0;

	for (int i = 0; i < super_block->data_block_amount; i++) {
		if (fat_entry->entries[i] == 0) {
			free_fat_blocks++;
		}
	}
	for (int i = 0; i < MAX_ROOT_ENTRIES; i++) {
		if (root_directory[i].file_name[0] == '\0') {
			free_root_entries++;
		}
	}

	printf("FS Info:\n");
	printf("total_blk_count=%d\n", super_block->total_block_amount);
	printf("fat_blk_count=%d\n", super_block->fat_block_amount);
	printf("rdir_blk=%d\n", super_block->root_block_index);
	printf("data_blk=%d\n", super_block->data_block_index);
	printf("data_blk_count=%d\n", super_block->data_block_amount);
	printf("fat_free_ratio=%d/%d\n", free_fat_blocks, super_block->data_block_amount);
	printf("rdir_free_ratio=%d/%d\n", free_root_entries, MAX_ROOT_ENTRIES);
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_ls(void)
{
	/* TODO: Phase 2 */
}

int fs_open(const char *filename)
{
	/* TODO: Phase 3 */
}

int fs_close(int fd)
{
	/* TODO: Phase 3 */
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

