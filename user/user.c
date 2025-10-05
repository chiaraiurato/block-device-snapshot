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
	int syscall_num1_activate = 156;
	int syscall_num2_deactivate = 174;
	int syscall_num3_restore = 177;
	//for loop device the devname is the path of the image file
	char *devname = "/home/aries/Documents/GitHub/block-device-snapshot/image";
	//this code is retrieved from the usctm module
	int ret = activate_or_deactivate_snapshot(syscall_num1_activate, devname, passw);
	printf("sys call %d returned value %d\n",syscall_num1_activate, ret);

}