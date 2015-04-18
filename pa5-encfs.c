#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#ifndef XATTR_USER_PREFIX
#define XATTR_USER_PREFIX "user."
#define XATTR_USER_PREFIX_LEN (sizeof (XATTR_USER_PREFIX) - 1)
#endif

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

// int aesCryptUtil(int cryptType, char *passKey, char *inPath, char *outPath){
// // int aesCryptUtil(int cryptType, char *passKey, FILE *inFile, FILE *outFile){

// 	// Open files
// 	FILE* inFile = NULL;
//   FILE* outFile = NULL;

// 	inFile = fopen(inPath, "rb");
//   if(!inFile){
//     perror("infile fopen error");
//     return EXIT_FAILURE;
//   }
//   outFile = fopen(outPath, "wb+");

//   if(!outFile){
//     perror("outfile fopen error");
//     return EXIT_FAILURE;
//   }

//   // Encryption

// 	if(!do_crypt(inFile, outFile, cryptType, passKey)){
// 		fprintf(stderr, "do_crypt failed\n");
//   }

//   // Cleanup
//   if(fclose(outFile)){
//       perror("outFile fclose error\n");
//   }
//   if(fclose(inFile)){
// 		perror("inFile fclose error\n");
//   }
//   return 0;
// }


// static void setXattr(char* name, char* value, char*path){
// 	char* tmpstr = NULL;
// 	tmpstr = malloc(strlen(name) + XATTR_USER_PREFIX_LEN + 1);
//   if(!tmpstr){
//     perror("malloc of 'tmpstr' error");
//     exit(EXIT_FAILURE);
//   }
//   strcpy(tmpstr, XATTR_USER_PREFIX);
//   strcat(tmpstr, name);
//   /* Set attribute */
//   if(setxattr(path, tmpstr, value, strlen(value), 0)){
//     perror("setxattr error");
//     fprintf(stderr, "path  = %s\n", path);
//     fprintf(stderr, "name  = %s\n", tmpstr);
//     fprintf(stderr, "value = %s\n", value);
//     fprintf(stderr, "size  = %zd\n", strlen(value));
//     exit(EXIT_FAILURE);
//   }
//   /* Cleanup */
//   free(tmpstr);
// }


// static void getXattr(const char *path, const char *name,
//                  char *value){
// 	char* tmpstr = NULL;
// 	tmpstr = malloc(strlen(name) + XATTR_USER_PREFIX_LEN + 1);
// 	if(!tmpstr){
//     perror("malloc of 'tmpstr' error");
//     exit(EXIT_FAILURE);
//   }
//   strcpy(tmpstr, XATTR_USER_PREFIX);
//   strcat(tmpstr, name);

//   // get size of value first
//   ssize_t valsize = 0;
//   valsize = getxattr(path, tmpstr, NULL, 0);

//   //Now get the vaule
//   char* tmpval = NULL;
//   tmpval = malloc(sizeof(*tmpval)*(valsize+1));
//   if(!tmpval){
//     perror("malloc of 'tmpval' error");
//     exit(EXIT_FAILURE);
//   }
//   valsize = getxattr(path, tmpstr, tmpval, valsize);

//   strcpy(value, tmpval);

//   /* Cleanup */
//   free(tmpval);
//   free(tmpstr);
// }


static void appendPath(char newPath[PATH_MAX], const char* path){
	strcpy(newPath, mirrorDir);
	strncat(newPath, path, PATH_MAX);
}

static void temporaryPath(char newPath[PATH_MAX], char tempPath[PATH_MAX]){
	strcpy(tempPath, newPath);
	strncat(tempPath, ".xmp_tmp", PATH_MAX);
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

	// char tempPath[PATH_MAX];
	// temporaryPath(newPath, tempPath);

	// aesCryptUtil(DECRYPT, keyPhrase, newPath, tempPath);

	res = open(newPath, fi->flags);
	if (res == -1)
		return -errno;

	// aesCryptUtil(ENCRYPT, keyPhrase, tempPath, newPath);

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	fprintf(stdout, "**************************************\n");
	fprintf(stdout, "Reading File\n");
	fprintf(stdout, "**************************************\n");

	// int fd;
	int res;

	(void) fi;
	(void) offset;

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	// Open file and Create Tempfile
	FILE * pFile = fopen (newPath,"r");
	FILE *tempfile = tmpfile();

	//if newpath has attribute:
	//then decrypt file
	do_crypt(pFile, tempfile, DECRYPT, keyPhrase);
	rewind(tempfile);
	rewind(pFile);
	//TODO: else:
	//copy file to tempfile
	// do_crypt(file, tempfile, COPY, keyPhrase);
	//

	// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
	// ptr = buffer, size = block size, nmemb = number of blocks
	res = fread(buf, 1, size, tempfile);
	if (res == -1)
		res = -errno;

	// close(tempfile);
	fclose(tempfile);
	fclose(pFile);

	// unlink(nameBuff);

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

	FILE * pFile = fopen (newPath,"r+");
	FILE *tempfile = tmpfile();

	do_crypt(pFile, tempfile, DECRYPT, keyPhrase);
	rewind(pFile);

	// size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)

	int fd = fileno(tempfile);
	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	rewind(tempfile);

	do_crypt(tempfile, pFile, ENCRYPT, keyPhrase);

	fclose(pFile);
	fclose(tempfile);


	// aesCryptUtil(ENCRYPT, keyPhrase, newPath, newPath);
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

	char newPath[PATH_MAX];
	appendPath(newPath, path);

	char tempPath[PATH_MAX];
	temporaryPath(newPath, tempPath);

	int res;

	res = unlink(tempPath);
	if (res == -1)
		return -errno;

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
