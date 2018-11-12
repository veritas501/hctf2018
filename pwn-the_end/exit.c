#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
	sleep(0);
	printf("here is a gift %p, good luck ;)\n",&sleep);
	fflush(stdout);
	close(1);
	close(2);
	unsigned long long addr;
	for(int i=0;i<5;i++){
		read(0,&addr,8);
		read(0,addr,1);
	}
	exit(1337);
}