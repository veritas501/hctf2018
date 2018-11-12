#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <ctype.h>
typedef void (*func)(void *,void *);

void add_seccomp(){
    scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_load(ctx);
}

//amd64
const char sc_start[] = "\x48\x89\xfc\x48\x89\xf0\x48\x31\xdb\x48\x31\xc9"
                        "\x48\x31\xd2\x48\x31\xff\x48\x31\xf6\x4d\x31\xc0"
                        "\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4"
                        "\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff\x48\x31\xed";

void check_sc(char *s){
    int len = strlen(s);
    for(int i=0;i<len;i++){
        if(!isalnum(s[i])){
            puts("Sorry i dont understand :(");
            exit(4);
        }
    }
}

void bar(){
    puts("ooooo   ooooo   .oooooo.   ooooooooooooo oooooooooooo");
    puts("`888'   `888'  d8P'  `Y8b  8'   888   `8 `888'     `8");
    puts(" 888     888  888               888       888        ");
    puts(" 888ooooo888  888               888       888oooo8   ");
    puts(" 888     888  888               888       888    \"  ");
    puts(" 888     888  `88b    ooo       888       888        ");
    puts("o888o   o888o  `Y8bood8P'      o888o     o888o       ");
    puts("");
    puts("============= Happy Christmas !!! =============");
    puts("");
}


int main(void){
    setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);

    void * handle;
    handle = dlopen("./libflag.so",RTLD_LAZY);
    if (!handle) {
        printf("dlopen libflag.so failed {%s}. tell admin pleace\n", dlerror());
        exit(EXIT_FAILURE);
    }

    bar();

    int fd = open("/dev/urandom",0);
    if(fd<0){
		printf("Open urandom error!!\n");
		exit(1);
	}
	void * rwx_addr;
    void * rw_addr;
	if(read(fd,&rwx_addr,sizeof(void *)) == -1){
		printf("Read urandom error!!\n");
		exit(2);
	}
    if(read(fd,&rw_addr,sizeof(void *)) == -1){
		printf("Read urandom error!!\n");
		exit(2);
	}
	rwx_addr = (void *)(((size_t)(rwx_addr)&~0xfff)%0x133700000000);
    rw_addr = (void *)(((size_t)(rw_addr)&~0xfff)%0x133700000000);
	void * rwx_page = mmap(rwx_addr,0x1000,7,34,-1,0);
    void * rw_page = mmap(rw_addr,0x1000,3,34,-1,0);
	if((rwx_page != rwx_addr) || (rw_page != rw_addr)){
		printf("mmap error!!\n");
		exit(3);
	}

    int sc_start_len = strlen(sc_start);
    strcpy(rwx_addr,sc_start);

    char buffer[0x1000];
    memset(buffer,0,0x1000);
    puts("Santa Claus hides the SECRCT FLAG in libflag.so , can you tell me how to find it??");
    int n = read(0,buffer,0x1000-sc_start_len);
    if(buffer[n-1] == '\n'){
        buffer[n-1]=0;
    }
    check_sc(buffer);
    strncpy(rwx_addr+sc_start_len,buffer,0x1000-sc_start_len);
    // read(0,rwx_addr+sc_start_len,0x1000-sc_start_len);
    add_seccomp();

    ((func)rwx_addr)(rw_addr+0x800,rwx_addr);
    return 0;
}