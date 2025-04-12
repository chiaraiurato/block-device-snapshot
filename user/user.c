#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

int activate_or_deactivate_snapshot(long int x, char *devname, char *passwd){
	return syscall(x, devname, passwd);
}
int main(int argc, char** argv){
	
	char* passw = "AOS{s3cr3t}";
	int syscall_num1 = 156;
	int syscall_num2 = 174;
	char *devname = "/home/aries/Documents/GitHub/block-device-snapshot/singlefile-FS/image";
	//this code is retrieved from the uctm module
	int ret = activate_or_deactivate_snapshot(syscall_num1, devname, passw);
	printf("sys call %d returned value %d\n",syscall_num1, ret);

}