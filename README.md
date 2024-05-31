# ECS 150: File System (ECS150-FS)

## Project Overview

This project aims to implement a basic file system called ECS150-FS. This file system is based on a FAT (File Allocation Table) and supports up to 128 files in a single root directory. The implementation involves mounting and unmounting a formatted partition, creating and deleting files, reading and writing files, and more.

## Features

### Core Features
1. **Superblock Management**: Manage the metadata of the file system including the number of blocks, size of the FAT, etc.
2. **File Allocation Table (FAT)**: Track free data blocks and map files to data blocks.
3. **Root Directory Management**: Handle file metadata, including filenames, sizes, and locations of data blocks.
4. **File Creation and Deletion**: Create and delete files in the virtual disk.
5. **File Reading and Writing**: Read from and write to files stored in the virtual disk.
6. **Mounting and Unmounting**: Mount and unmount the virtual disk.
7. **Formatted Disk**: Use a provided formatter to create a virtual disk.

### Constraints
- Written in C and compiled with GCC.
- Only standard functions from the GNU C Library (libc) are used.
- Consistent coding style and proper commenting.

## File System Specifications

### Superblock
The superblock is the first block of the file system and contains the following metadata:

| Offset | Length (bytes) | Description                              |
|--------|----------------|------------------------------------------|
| 0x00   | 8              | Signature (must be equal to “ECS150FS”)  |
| 0x08   | 2              | Total amount of blocks of virtual disk   |
| 0x0A   | 2              | Root directory block index               |
| 0x0C   | 2              | Data block start index                   |
| 0x0E   | 2              | Amount of data blocks                    |
| 0x10   | 1              | Number of blocks for FAT                 |
| 0x11   | 4079           | Unused/Padding                           |

### File Allocation Table (FAT)
The FAT is an array of 16-bit unsigned words, with entries tracking data blocks:

- First entry (0) is always FAT_EOC (0xFFFF).
- Entries marked as 0 are free data blocks.
- Positive values link to the next block in the chainmap.

Example FAT structure:

| FAT index | 0      | 1 | 2 | 3 | 4 | 5 | 6      | 7 | 8      | 9 | 10 | … |
|-----------|--------|---|---|---|---|---|--------|---|--------|---|----|---|
| Content   | 0xFFFF | 8 | 3 | 4 | 5 | 6 | 0xFFFF | 0 | 0xFFFF | 0 | 0  | … |

### Root Directory
The root directory is an array of 128 entries, each 32 bytes, describing a file:

| Offset | Length (bytes) | Description                   |
|--------|----------------|-------------------------------|
| 0x00   | 16             | Filename (including NULL)     |
| 0x10   | 4              | Size of the file (in bytes)   |
| 0x14   | 2              | Index of the first data block |
| 0x16   | 10             | Unused/Padding                |

### Formatting Program
Use the provided formatter to create a new virtual disk with a specified number of data blocks:

```bash
$ ./fs_make.x disk.fs 4096
Created virtual disk 'disk.fs' with '4096' data blocks
```

### Reference Program and Testing
A reference program is provided to perform various operations on the virtual disk, such as retrieving information, listing files, etc.

Example usage to match output:

```bash
$ ./fs_make.x disk.fs 8192
Creating virtual disk 'disk.fs' with '8192' data blocks
$ ./fs_ref.x info disk.fs > ref_output
$ ./test_fs.x info disk.fs > my_output
$ diff ref_output my_output
```
