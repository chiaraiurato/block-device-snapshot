#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

int activate_snapshot(long int x, char *devname, char *passwd){
	return syscall(x, devname, passwd);
}
int deactivate_snapshot(long int x, char *devname, char *passwd){
	return syscall(x, devname, passwd);
}

int main(int argc, char** argv){
	
	char* passw = "AOS{s3acr3t}";
	int syscall_num = 156;
	//this code is retrieved from the uctm module
	int ret = activate_snapshot(syscall_num, "/dev/sda", passw);
	printf("sys call %d returned value %d\n",syscall_num, ret);

}