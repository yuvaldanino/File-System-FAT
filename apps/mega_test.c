#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fs.h>

#define ASSERT(cond, func)                               \
do {                                                     \
	if (!(cond)) {                                       \
        printf("\033[0;31m");                            \
        printf("Function '%s' FAILED\n", func);          \
        printf("\033[0m");                               \
		exit(EXIT_FAILURE);                              \
	}                                                    \
    else {                                               \
        printf("\033[0;32m");                            \
        printf("Function '%s' PASSED\n", func);          \
        printf("\033[0m");                               \
    }                                                    \
} while (0)

int rand_characters(int argc, char *argv[]) {
	int ret;
	char *diskname;
	int fd;
	const int CHAR_SIZE = 34;
	char data[CHAR_SIZE];

	if (argc < 1) {
		printf("Usage: %s <diskimage>\n", argv[0]);
		exit(1);
	}

	/* Mount disk */
	diskname = argv[1];
	ret = fs_mount(diskname);
	ASSERT(!ret, "fs_mount");

	/* Open file */
	fd = fs_open("File-dKvwu.txt");
	ASSERT(fd >= 0, "fs_open");

	/* Read some data */
	fs_lseek(fd, 0);
	ret = fs_read(fd, data, 27);
	ASSERT(ret == 27, "fs_read: ret value");

	/* Close file and unmount */
	fs_close(fd);
	fs_umount();

    return 0;
}

int read_1mb(int argc, char *argv[]) {
	int ret;
	char *diskname;
	int fd;
	const int CHAR_SIZE = 1049600;
	char data[CHAR_SIZE];

	if (argc < 1) {
		printf("Usage: %s <diskimage>\n", argv[0]);
		exit(1);
	}

	/* Mount disk */
	diskname = argv[1];
	ret = fs_mount(diskname);
	ASSERT(!ret, "fs_mount");

	/* Open file */
	fd = fs_open("File-dKvwu.txt");
	ASSERT(fd >= 0, "fs_open");

	/* Read some data */
	fs_lseek(fd, 0);
	ret = fs_read(fd, data, 1049600);
	ASSERT(ret == 1049600, "fs_read: ret value");

	/* Close file and unmount */
	fs_close(fd);
	fs_umount();

    return 0;
}

int empty_read (int argc, char *argv[]) {
	int ret;
	char *diskname;
	int fd;
	//const int CHAR_SIZE = 0;
	char data[0];

	if (argc < 1) {
		printf("Usage: %s <diskimage>\n", argv[0]);
		exit(1);
	}

	/* Mount disk */
	diskname = argv[1];
	ret = fs_mount(diskname);
	ASSERT(!ret, "fs_mount");

	/* Open file */
	fd = fs_open("File-dKvwu.txt");
	ASSERT(fd >= 0, "fs_open");

	/* Read some data */
	fs_lseek(fd, 0);
	ret = fs_read(fd, data, 0);
	ASSERT(ret == 0, "fs_read: ret value");

	/* Close file and unmount */
	fs_close(fd);
	fs_umount();

    return 0;
}

void add_large(void) {
	int ret;
	char *diskname;
	int fd;
	const int CHAR_SIZE = 1550336;
	char data[CHAR_SIZE];

	/* Mount disk */
	diskname = "large_disk.fs";
	ret = fs_mount(diskname);
	ASSERT(!ret, "fs_mount");

	/* Open file */
	fd = fs_open("large.txt");
	ASSERT(fd >= 0, "fs_open");

	/* Read some data */
	fs_lseek(fd, 0);
	ret = fs_read(fd, data, CHAR_SIZE);
	ASSERT(ret == CHAR_SIZE, "fs_read: ret value");

	/* Close file and unmount */
	fs_close(fd);
    ret = fs_delete("large.txt");
    ASSERT(!ret, "fs_delete");
    ret = fs_stat(fd);
    ASSERT(ret == -1, "fs_stat");
	fs_umount();
}

void invalid_filename(void) {
	int ret;
	char *diskname;
	int fd;

	/* Mount disk */
	diskname = "large_disk.fs";
	ret = fs_mount(diskname);
	ASSERT(!ret, "fs_mount");

	/* Open file */
	fd = fs_open("largeeeeeeeeeeeeeeeeeeeee.txt");
	ASSERT(fd < 0, "fs_open");

	/* Close file and unmount */
	fs_close(fd);
	fs_umount();
}

int file_not_open(int argc, char *argv[]) {
	int ret;
	char *diskname;
	int fd;
	//const int CHAR_SIZE = 0;
	char data[0];

	if (argc < 1) {
		printf("Usage: %s <diskimage>\n", argv[0]);
		exit(1);
	}

	/* Mount disk */
	diskname = argv[1];
	ret = fs_mount(diskname);
	ASSERT(!ret, "fs_mount");

	/* Open file */
	fd = fs_open("File-dKvwu.txt");
	ASSERT(fd >= 0, "fs_open");

    fs_close(fd);

	/* Read some data */
	fs_lseek(fd, 0);
	ret = fs_read(fd, data, 0);
	ASSERT(ret == -1, "fs_read: ret value");

	/* Close file and unmount */
	fs_umount();

    return 0;
}

void dup_file(int argc, char *argv[]) {
	int ret;
	char *diskname;
	int fd;

	/* Mount disk */
	diskname = "large_disk.fs";
	ret = fs_mount(diskname);
	ASSERT(!ret, "fs_mount");

	/* Open file */
	fd = fs_create("File-dKvwu.txt");
    ASSERT(fd == -1, "fs_create");

	/* Close file and unmount */
	fs_close(fd);
	fs_umount();
}

void too_many_files() {
    // create different files
	int ret;
	char *diskname;
	//int fd;
	//const int CHAR_SIZE = 1550336;
	//char data[CHAR_SIZE];

	/* Mount disk */
	diskname = "32files.fs";
	ret = fs_mount(diskname);
	ASSERT(!ret, "fs_mount");

	/* Open file */
    for (int i = 0; i < 128; i++) {
        int i_cpy = i;
        char j [] = {i_cpy+'0', '\n'};
        ret = fs_create(j);
        if (ret < 0) {
            printf("aborted at %d\n", i);
            break;
        }
    }

    ASSERT(!ret, "fs_create 128 files");

	/* Close file and unmount */
	// fs_close(fd);
    ASSERT(ret == -1, "fs_stat");
	fs_umount();
}

int main(int argc, char *argv[]) {

    printf("\nrand characters:\n");
    rand_characters(argc, argv);

    printf("\nread_1mb:\n");
    read_1mb(argc, argv);

    printf("\nempty_read\n");
    empty_read(argc, argv);

    printf("\ninvalid_filename\n");
    invalid_filename();

    printf("\nfile_not_open\n");
    file_not_open(argc, argv);

    printf("\ndup_file\n");
    dup_file(argc, argv);

    printf("\ntoo_many_files\n");
    too_many_files();

	return 0;
}