#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#define XATTR_ENCRYPTED "user.encrypted"

#include <fuse.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include "aes-crypt.h"
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

const int ENCRYPT = 1;
const int DECRYPT = 0;
const int COPY = -1;

char * mirrorDir;
char * keyPhrase;

/* function for appending our mirror path to the path name */
static void appendPath(char newPath[PATH_MAX], const char* path){
	strcpy(newPath, mirrorDir);
	strncat(newPath, path, PATH_MAX);
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = lstat(newPath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = access(newPath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = readlink(newPath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	dp = opendir(newPath);
	if (dp == NULL)
		return -errno;
	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(newPath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = mkdir(newPath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = unlink(newPath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = rmdir(newPath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = chmod(newPath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = lchown(newPath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = truncate(newPath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(newPath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	fprintf(stdout, "**************************************\n");
	fprintf(stdout, "opening File\n");
	fprintf(stdout, "**************************************\n");

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = open(newPath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	fprintf(stdout, "**************************************\n");
	fprintf(stdout, "Reading File\n");
	fprintf(stdout, "**************************************\n");

	int res;

	(void) fi;
	(void) offset;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	// Open file and Create Tempfile
	FILE * pFile = fopen (newPath,"r");
	FILE *tempfile = tmpfile();

	// Get attributes for
	int value = 0;
	getxattr(newPath, XATTR_ENCRYPTED, &value, sizeof(value));
	fprintf(stdout, "XATTR VALUE IS: %d\n", value);

	// Depending on the attribute value, decrypt or copy
	int action = value ? DECRYPT : COPY;
	do_crypt(pFile, tempfile, action, keyPhrase);

	// Move pointer back to head of files.
	rewind(tempfile);
	rewind(pFile);

	// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
	// ptr = buffer, size = block size, nmemb = number of blocks
	res = fread(buf, 1, size, tempfile);
	if (res == -1)
		res = -errno;

	// Cleanup
	fclose(tempfile);
	fclose(pFile);

	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	fprintf(stdout, "**************************************\n");
	fprintf(stdout, "Writing File\n");
	fprintf(stdout, "**************************************\n");

	int res;
	(void) offset;
	(void) fi;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	// Open the file for reading AND writing
	FILE * pFile = fopen (newPath,"r+");
	FILE *tempfile = tmpfile();

	// Get Xattr to determin if we need to decrpyt
	int value = 0;
	getxattr(newPath, XATTR_ENCRYPTED, &value, sizeof(value));
	fprintf(stdout, "XATTR VALUE IS: %d\n", value);

	// Depending on the attribute value, decrypt or copy
	int action = value? DECRYPT: COPY;
	do_crypt(pFile, tempfile, action, keyPhrase);
	rewind(pFile);

  // Get file descriptor of tempfile to use with pwrite
	int fd = fileno(tempfile);
	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	//Rewind file pointer to start of file for tempfile
	rewind(tempfile);

	// Only encrypt if it was a previously encrypted file
	action = (action == DECRYPT) ?  ENCRYPT : COPY;
	do_crypt(tempfile, pFile, action, keyPhrase);

	// Cleanup
	fclose(pFile);
	fclose(tempfile);

	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	res = statvfs(newPath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

  (void) fi;

  int res;

  char newPath[PATH_MAX];
	appendPath(newPath, path);

  res = creat(newPath, mode);
  if(res == -1)
		return -errno;

	// Encrypt files created in fuse filesystem
	int encryptValue = 1;
	int ret = setxattr(newPath, XATTR_ENCRYPTED, &encryptValue, sizeof(encryptValue), 0);
	if (ret == -1){
		fprintf(stdout, "THE VALUE ENCODING FAILED\n");
		return -errno;
	}

  close(res);

  return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	fprintf(stdout, "**************************************\n");
	fprintf(stdout, "Release File\n");
	fprintf(stdout, "**************************************\n");
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */


	(void) fi;
	(void) path;

	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char newPath[PATH_MAX];
	appendPath(newPath, path);

	int res = lsetxattr(newPath, name, value, size, flags);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char newPath[PATH_MAX];
	appendPath(newPath, path);

	int res = lgetxattr(newPath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char newPath[PATH_MAX];
	appendPath(newPath, path);

	int res = llistxattr(newPath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	char newPath[PATH_MAX];
	appendPath(newPath, path);

	int res = lremovexattr(newPath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

void usage(){
	printf("Usage: ./pa5-encfs <key-phrase> <mirror-dir> <mount-point> [options]");
}

int main(int argc, char *argv[])
{
	if(argc <= 3){
	  usage();
	  exit(EXIT_FAILURE);
    }

    keyPhrase = argv[1];
    mirrorDir = realpath(argv[2], NULL);

    if (mirrorDir == NULL){
    	printf("Failed loading mirror directory\n");
    	exit(EXIT_FAILURE);
    }
    if (realpath(argv[3], NULL) == NULL){
    	printf("Failed loading mount point\n");
    	exit(EXIT_FAILURE);
    }

    printf("Key Phrase: %s \n", keyPhrase);
    printf("Mirror Directory: %s \n", mirrorDir);

    int i;
    for ( i = 3; i < argc; i++){
    	argv[i-2] = argv[i];
    }
    argv[argc-1] = NULL;
    argv[argc-2] = NULL;
    argc -= 2;

	umask(0);
	return fuse_main(argc, argv, &xmp_oper, NULL);
}
