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
#define FAT_ENTRIES 8192
#define BLOCK_SIZE 4096 
#define MAX_FILENAME 16 
#define FAT_EOC 0xFFFF 

#define min(a, b) ((a) < (b) ? (a) : (b))

//superblock 
typedef struct __attribute__((packed)) {
	uint8_t signature[SIGNATURE_LENGTH]; 
	uint16_t total_block_amount;
	uint16_t root_block_index;
	uint16_t data_block_index;
	uint16_t data_block_amount;
	uint8_t fat_block_amount;
	uint8_t padding[SUPERBLOCK_PADDING];
} SuperBlock;

//single block of FAT
typedef struct __attribute__((packed)) {
	uint16_t entries[BLOCK_SIZE/2];
} FAT;

typedef struct __attribute__((packed)) {
	uint8_t file_name[MAX_FILENAME];
	uint32_t file_size;
	uint16_t first_data_block_index;
	uint8_t padding[ROOT_PADDING];
} RootEntry;

typedef struct __attribute__((packed)) {
	uint16_t offset;
	uint8_t index;
	int in_use; 
} FileDescriptor;

static  SuperBlock *super_block;
static  FAT *fat_entries;
static  RootEntry *RootEntryArray;
static  FileDescriptor *fd_table[FS_OPEN_MAX_COUNT];

int free_memory(void) {
    if (super_block) {
        free(super_block);
        super_block = NULL;
    }

    if (fat_entries) {
        free(fat_entries);
        fat_entries = NULL;
    }

    if (RootEntryArray) {
        free(RootEntryArray);
        RootEntryArray = NULL;
    }
}

int fs_mount(const char *diskname)
{
	// Open virtual disk
	if (block_disk_open(diskname) != 0) {
		return -1;
	}
	// Read super_block at beginning of virtual disk
	super_block = malloc(sizeof(SuperBlock));
	if (!super_block || block_read(0, super_block) == -1) {
        fprintf(stderr, "Error: unable to read the superblock from disk.\n");
        free_memory();
        block_disk_close();
        return -1;
    }
	// Verify signature has correct signature
	if (memcmp(super_block->signature, SIGNATURE, SIGNATURE_LENGTH) != 0) {
		fprintf(stderr, "Error: disk signature doesn't match.\n");
        free_memory();
        block_disk_close();
        return -1;
	}

	// Verify super_block has correct block amount
	if (super_block->total_block_amount != block_disk_count()) {
		fprintf(stderr, "Error: super_block has wrong block amount.\n");
        free_memory();
    	block_disk_close();
		return -1;
	}

	// Read blocks into a FAT array
	fat_entries = malloc(sizeof(FAT) * super_block->fat_block_amount);
	if (!fat_entries) {
        fprintf(stderr, "Error: unable to allocate memory for the FAT.\n");
        free_memory();
        block_disk_close();
        return -1;
    }

	// Read the FAT blocks from disk
	for (int i = 0; i < super_block->fat_block_amount; i++) {
		if (block_read(1 + i, &fat_entries[i]) == -1) {
            free_memory();
			return -1; // Handle read failure
		}
	}

	// Allocate memory for the root directory entries
    RootEntryArray = malloc(MAX_ROOT_ENTRIES * sizeof(RootEntry));
    if (RootEntryArray == NULL) {
        free_memory();
        return -1; // Handle memory allocation failure
    }	

	// Read the root directory block from disk
    if (block_read(super_block->root_block_index, RootEntryArray) == -1) {
        free_memory();
        return -1;
    }

    // Initialize the file descriptor table
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        fd_table[i] = NULL; // Set each file descriptor to NULL, indicating it's not in use
    }

	return 0;
}

int is_mounted(void) {
    return (super_block != NULL && fat_entries != NULL && RootEntryArray != NULL);
}

int fs_umount(void)
{
	if (!is_mounted()) {
        fprintf(stderr, "Error: Filesystem is not mounted.\n");
        return -1;
    }

	// Free dynamically allocated memory
    free_memory();

    // Close virtual disk
    if (block_disk_close() == -1) {
        fprintf(stderr, "Error: Unable to close virtual disk.\n");
		return -1; // Closing the virtual disk failed
    }

	return 0;
}

int fs_info(void)
{
	if (!is_mounted()) {
        fprintf(stderr, "Error: Filesystem is not mounted.\n");
        return -1;
    }

    printf("FS Info:\n");
    printf("total_blk_count=%d\n", super_block->total_block_amount);
    printf("fat_blk_count=%d\n", super_block->fat_block_amount);
    printf("rdir_blk=%d\n", super_block->root_block_index);
    printf("data_blk=%d\n", super_block->data_block_index);
    printf("data_blk_count=%d\n", super_block->data_block_amount);

    // Count free blocks in the FAT
    int free_fat_blocks = 0;
    for (int i = 0; i < super_block->data_block_amount; i++) {
		if (fat_entries->entries[i] == 0){
			free_fat_blocks++;
		}
	}

    // Count free root directory entries
    int free_root_entries = 0;
    for (int i = 0; i < MAX_ROOT_ENTRIES; i++) {
        if (RootEntryArray[i].file_name[0] == '\0') { // Assuming an empty filename indicates a free entry
            free_root_entries++;
        }
    }

    // Print the ratios of free FAT blocks to total data blocks, and free root directory entries to maximum root entries
    printf("fat_free_ratio=%d/%d\n", free_fat_blocks, super_block->data_block_amount);
    printf("rdir_free_ratio=%d/%d\n", free_root_entries, MAX_ROOT_ENTRIES);

	return 0;
}

int is_valid_filename(const char* filename) {
    return (filename && strlen(filename) > 0 && strlen(filename) < MAX_FILENAME);
}

int fs_create(const char *filename)
{
	if (!is_mounted()) {
        fprintf(stderr, "Error: Filesystem is not mounted.\n");
        return -1;
    }

	if (!is_valid_filename(filename)) {
        fprintf(stderr, "Error: Filename is invalid or too long.\n");
        return -1;
    }

	// Check for existing file with the same name
    for (int i = 0; i < MAX_ROOT_ENTRIES; i++) {
        if (strcmp((char *)RootEntryArray[i].file_name, filename) == 0) {
            fprintf(stderr, "Error: File already exists.\n");
            return -1;
        }
    }

	// Look for an empty entry in RootEntryArray
    int emptyEntry = -1;
    for (int i = 0; i < MAX_ROOT_ENTRIES; i++) {
        if (RootEntryArray[i].file_name[0] == '\0') { // Empty entry found
            emptyEntry = i;
            break;
        }
    }

    if (emptyEntry == -1) {
        fprintf(stderr, "Error: Root directory is full.\n");
        return -1;
    }

	// Create the file by initializing RootEntry
    strcpy((char *)RootEntryArray[emptyEntry].file_name, filename);
    RootEntryArray[emptyEntry].file_size = 0;
    RootEntryArray[emptyEntry].first_data_block_index = FAT_EOC; // Indicating no data blocks are allocated yet

    // Write updated RootEntryArray back to disk
    if (block_write(super_block->root_block_index, RootEntryArray) == -1) {
        fprintf(stderr, "Error: Unable to write RootEntryArray to disk.\n");
        return -1;
    }

    return 0;
}

int fs_delete(const char *filename)
{
    if (!is_mounted) {
        fprintf(stderr, "Error: Filesystem is not mounted.\n");
        return -1;
    }

    if (!is_valid_filename(filename)) {
        fprintf(stderr, "Error: Filename is invalid or too long.\n");
        return -1;
    }
    // Check if file exists
    int fileIndex = -1;
    for (int i = 0; i < MAX_ROOT_ENTRIES; i++) {
        if (strcmp((char *)RootEntryArray[i].file_name, filename) == 0) {
            fileIndex = i;
            break;
        }
    }
    if (fileIndex == -1) {
        fprintf(stderr, "Error: File not found.\n");
        return -1;
    }

    // Free allocated FAT entries
    uint16_t currentBlock = RootEntryArray[fileIndex].first_data_block_index;
    while (currentBlock != FAT_EOC) {
        int fatBlockIndex = currentBlock / (BLOCK_SIZE / sizeof(uint16_t));
        uint16_t nextBlockIndex = fat_entries[fatBlockIndex].entries[currentBlock % (BLOCK_SIZE / sizeof(uint16_t))];
        fat_entries[fatBlockIndex].entries[currentBlock % (BLOCK_SIZE / sizeof(uint16_t))] = 0;  // Mark the block as free
        
        // Write the modified FAT block back to disk
        // Assuming FAT starts immediately after the superblock, at block 1
        int diskBlockNum = 1 + fatBlockIndex; // Add 1 to account for the superblock at block 0
        if (block_write(diskBlockNum, &fat_entries[fatBlockIndex]) == -1) {
            fprintf(stderr, "Error: Unable to write FAT block to disk.\n");
            return -1;
        }

        currentBlock = nextBlockIndex;
    }

    memset(&RootEntryArray[fileIndex], 0, sizeof(RootEntry));

    // Write the updated root directory back to disk
    if (block_write(super_block->root_block_index, RootEntryArray) == -1) {
        fprintf(stderr, "Error: Unable to write RootEntryArray to disk.\n");
        return -1;
    }

    return 0;
}

int fs_ls(void)
{
    if (!is_mounted()) {
        fprintf(stderr, "Error: Filesystem is not mounted.\n");
        return -1;
    } 

    printf("FS Ls:\n");

    // Iterate through the Root Directory
    for (int i = 0; i < MAX_ROOT_ENTRIES; i++) {
        // Check if the entry is valid (non-empty)
        if (RootEntryArray[i].file_name[0] != '\0') {
            printf("file: %s, size: %d, data_blk: %d\n",
                   RootEntryArray[i].file_name,
                   RootEntryArray[i].file_size,
                   RootEntryArray[i].first_data_block_index);
        }
    }

    return 0;
}

int fs_open(const char *filename)
{
    int fd = -1;
    if (!is_mounted()) {
        fprintf(stderr, "Error: Filesystem is not mounted.\n");
        return -1;  // Filesystem not mounted
    }

    if (!is_valid_filename(filename)) {
        fprintf(stderr, "Error: Filename is invalid or too long.\n");
        return -1;
    }
    // Check if file exists
    int fileIndex = -1;
    for (int i = 0; i < MAX_ROOT_ENTRIES; i++) {
        if (strcmp((char *)RootEntryArray[i].file_name, filename) == 0) {
            fileIndex = i;
            break;
        }
    }
    // Check if file is found 
    if (fileIndex == -1) {
        fprintf(stderr, "Error: File not found.\n");
        return -1;
    }

    // Look for spot in file descriptor table.
    // Available spots set to NULL when mounting to establish an empty table.
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        if (fd_table[i] == NULL) {  // Found an available spot
            fd_table[i] = malloc(sizeof(FileDescriptor));
            if (fd_table[i] == NULL) {
                fprintf(stderr, "Failed to allocate memory for FD.\n");
                return -1;  // Failed to allocate memory for FD
            }
            fd_table[i]->offset = 0;  // Initialize file offset to 0
            fd_table[i]->index = fileIndex;  // Store the index of the file in the root directory
            fd_table[i]->in_use = 1;  // Mark FD as in use
            fd = i;  // FD is the index in the fd_table
            break;
        }
    }

    if (fd == -1) {
        fprintf(stderr, "Error: No available file descriptor spot.\n");
        return -1;  // No available file descriptor spot
    }
    
    return fd;  // Return the file descriptor
}

int fs_close(int fd)
{
    // Check if the file descriptor is within the valid range
    if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) {
        fprintf(stderr, "FD %d is not in valid range [0, %d).\n", fd, FS_OPEN_MAX_COUNT);
        return -1; // Invalid file descriptor
    }

    // Check if the file descriptor is actually in use
    if (fd_table[fd] == NULL || fd_table[fd]->in_use == 0) {
        fprintf(stderr, "File not in use\n");
        return -1; // File descriptor not in use or invalid
    }

    // Free the allocated memory for the file descriptor
    free(fd_table[fd]);
    // Mark the slot as available again
    fd_table[fd] = NULL;

    return 0; // Successful closure
}

int is_valid_fd(int fd) {
    return (fd >= 0 && fd < FS_OPEN_MAX_COUNT && fd_table[fd] != NULL && fd_table[fd]->in_use != 0);
}

int fs_stat(int fd)
{
    if (!is_mounted()) {
        fprintf(stderr, "Error: Filesystem is not mounted.\n");
        return -1;
    }

    if (!is_valid_fd(fd)) {
        fprintf(stderr, "Error: Invalid file descriptor.\n");
        return -1;
    }

    // Retrieve and return the size of the file associated with the file descriptor
    return RootEntryArray[fd_table[fd]->index].file_size;
}

int fs_lseek(int fd, size_t offset)
{
    if (!is_mounted()) {
        fprintf(stderr, "Error: Filesystem is not mounted.\n");
        return -1;
    }

    if (!is_valid_fd(fd)) {
        fprintf(stderr, "Error: Invalid file descriptor.\n");
        return -1;
    }

    // Get the size of the file associated with the file descriptor
    size_t fileSize = RootEntryArray[fd_table[fd]->index].file_size;

    // Validate the offset
    if (offset > fileSize) {
        fprintf(stderr, "Error: Offset is larger than the file size.\n");
        return -1;
    }

    fd_table[fd]->offset = offset;

    return 0; 
}




int fs_read(int fd, void *buf, size_t count) {
    if (!is_mounted() || fd < 0 || fd >= FS_OPEN_MAX_COUNT || buf == NULL || fd_table[fd] == NULL) {
        fprintf(stderr, "Error: failed intial check read.\n");
        return -1; // Check for mounted FS, valid FD, and non-null buffer
    }

    FileDescriptor *fileDesc = fd_table[fd];
    uint16_t currentBlock = RootEntryArray[fileDesc->index].first_data_block_index;
    size_t fileOffset = fileDesc->offset;
    size_t bytesToRead = min(count, RootEntryArray[fileDesc->index].file_size - fileOffset);
    size_t bytesRead = 0;

    char *bounceBuffer = malloc(BLOCK_SIZE); // Using a bounce buffer for each block read
    if (!bounceBuffer) {
        fprintf(stderr, "Error: Failed to allocate bounce buffer.\n");
        return -1; // Failed to allocate bounce buffer
    }

    while (bytesToRead > 0 && currentBlock != FAT_EOC) {
        int blockIndex = super_block->data_block_index + currentBlock; // Calculate actual block index
        block_read(blockIndex, bounceBuffer);

        size_t blockOffset = fileOffset % BLOCK_SIZE;
        size_t bytesInBlock = min(BLOCK_SIZE - blockOffset, bytesToRead);
        
        memcpy(buf + bytesRead, bounceBuffer + blockOffset, bytesInBlock);

        bytesRead += bytesInBlock;
        bytesToRead -= bytesInBlock;
        fileOffset += bytesInBlock;

        if (bytesInBlock < BLOCK_SIZE - blockOffset || currentBlock == FAT_EOC) {
            break; // Either we've read the requested bytes or reached the end of file
        }

        currentBlock = fat_entries[currentBlock].entries[0]; // Move to next block in the chain
    }

    fileDesc->offset += bytesRead; // Update the file descriptor's offset

    free(bounceBuffer); // Free the allocated bounce buffer

    return bytesRead; // Return the number of bytes read
}

uint16_t allocate_block() {
    // Iterate through the FAT to find a free block
    for (uint16_t i = 1; i < super_block->data_block_amount; ++i) {  // Start from 1 since 0 is reserved
        uint16_t fatBlock = i / (BLOCK_SIZE / sizeof(uint16_t)); // Which FAT block the entry is in
        uint16_t entryIndex = i % (BLOCK_SIZE / sizeof(uint16_t)); // Entry index within the FAT block

        if (fat_entries[fatBlock].entries[entryIndex] == 0) {  // If the entry is free
            fat_entries[fatBlock].entries[entryIndex] = FAT_EOC;  // Mark it as the end of a chain

            // Write the updated FAT block back to disk
            if (block_write(super_block->data_block_index + fatBlock, &fat_entries[fatBlock]) == -1) {
                fprintf(stderr, "Failed to write FAT block to disk\n");
                return FAT_EOC;  // Return an error if writing the FAT block fails
            }

            // Return the actual block number, considering the data block start index
            return super_block->data_block_index + i;
        }
    }
    // If no free block is found, return FAT_EOC to indicate failure
    return FAT_EOC;
}



int fs_write(int fd, void *buf, size_t count) {
    if (!super_block || !fat_entries || !RootEntryArray || fd < 0 || fd >= FS_OPEN_MAX_COUNT || fd_table[fd] == NULL || buf == NULL) {
        fprintf(stderr, "Error: failed write intial state.\n");

        return -1;
    }

    size_t bytesWritten = 0; 
    uint16_t currentBlock = RootEntryArray[fd_table[fd]->index].first_data_block_index;
    uint16_t previousBlock = FAT_EOC;
    size_t fileOffset = fd_table[fd]->offset;
    size_t remaining = count;

    while (remaining > 0) {
        if (currentBlock == FAT_EOC) {
            // Allocate a new block and update FAT as necessary
            currentBlock = allocate_block(); 
            if (currentBlock == FAT_EOC) {
                break; // No more space available
            }
            if (previousBlock != FAT_EOC) {
                fat_entries[previousBlock].entries[0] = currentBlock;
            } else {
                RootEntryArray[fd_table[fd]->index].first_data_block_index = currentBlock;
            }
        }

        char blockBuffer[BLOCK_SIZE];
        if (block_read(super_block->data_block_index + currentBlock, blockBuffer) == -1) {
            fprintf(stderr, "Error reading block\n");
            break; // Error reading block
        }

        size_t offsetInBlock = fileOffset % BLOCK_SIZE;
        size_t spaceInBlock = BLOCK_SIZE - offsetInBlock;
        size_t bytesInThisStep = min(spaceInBlock, remaining);

        // Copy data to the block buffer and write it back
        memcpy(blockBuffer + offsetInBlock, buf + bytesWritten, bytesInThisStep);
        if (block_write(super_block->data_block_index + currentBlock, blockBuffer) == -1) {
            fprintf(stderr, "Error writing block\n");

            break; // Error writing block
        }

        bytesWritten += bytesInThisStep;
        remaining -= bytesInThisStep;
        fileOffset += bytesInThisStep;

        if (bytesInThisStep == spaceInBlock) {
            previousBlock = currentBlock;
            currentBlock = fat_entries[currentBlock].entries[0]; // Move to the next block
        }
    }

    // Update file descriptor and file size
    fd_table[fd]->offset += bytesWritten;
    if (fd_table[fd]->offset > RootEntryArray[fd_table[fd]->index].file_size) {
        RootEntryArray[fd_table[fd]->index].file_size = fd_table[fd]->offset;
    }

    return bytesWritten; // Return the number of bytes actually written
}