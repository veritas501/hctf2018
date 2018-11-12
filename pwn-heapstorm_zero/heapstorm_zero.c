#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

struct mylist{
	size_t xorkey;
	char * chunk[0x20];
};
int sum;

struct mylist * page;

void bar(){
	puts("ooooo   ooooo   .oooooo.   ooooooooooooo oooooooooooo");
	puts("`888'   `888'  d8P'  `Y8b  8'   888   `8 `888'     `8");
	puts(" 888     888  888               888       888        ");
	puts(" 888ooooo888  888               888       888oooo8   ");
	puts(" 888     888  888               888       888    \"  ");
	puts(" 888     888  `88b    ooo       888       888        ");
	puts("o888o   o888o  `Y8bood8P'      o888o     o888o       ");
	puts("");
	puts("===== (fake) HEAP STORM ZERO =====");
	puts("");
}

void init(){
	sum=0;
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	int fd = open("/dev/urandom",0);
	if(fd<0){
		printf("Open urandom error!!\n");
		exit(-1);
	}
	void * pageaddr;
	if(read(fd,&pageaddr,sizeof(void *)) == -1){
		printf("Read urandom error!!\n");
		exit(-1);
	}
	pageaddr = (void *)(((size_t)(pageaddr)&~0xfff)%0x133700000000);
	page = mmap(pageaddr,0x1000,3,34,-1,0);
	if(page != pageaddr){
		printf("mmap error!!\n");
		exit(-1);
	}

	if(read(fd,&(page->xorkey),sizeof(size_t)) == -1){
		printf("Read urandom error!!\n");
		exit(-1);
	}

	for(int i=0;i<0x20;i++){
		page->chunk[i]=(char *)page->xorkey;
	}
	bar();
	close(fd);
}

int menu_getinput(){
	int n=0;
	puts("1. Allocate");
	puts("2. View");
	puts("3. Delete");
	puts("4. Exit");
	printf("Choice:");
	scanf("%d",&n);
	return n;
}

void read_n(char *buf,size_t len){
	char ch;
	int i;
	for (i = 0; i < len; ++i )
	{
		ch = 0;
		if ( read(0, &ch, 1) < 0 ){
			puts("Read error!!\n");
			exit(1);
		}
		buf[i] = ch;
		if (ch == '\n'){
			break;
		}
	}
	buf[i] = 0;
}

int read_int(){
	char buf[0x8];
	memset(buf,0,0x8);
	read_n(buf,8);
	return atoi(buf);
}


int check_chunksize(int size){
	return (size > 0 && size<=0x38);
}

void Allocate(){
	int i;
	if(sum > 0x20u){
		puts("Too many chunks!");
		exit(-1);
	}
	printf("Please input chunk size:");
	int size = read_int();
	if(!check_chunksize(size)){
		puts("Invalid size!");
		exit(-1);
	}
	
	char * p = (char *)calloc(size, 1);
	if(!p){
		puts("Alloc error!!");
		exit(-1);
	}
	printf("Please input chunk content:");
	read_n(p, size);
	for ( i = 0; i <= 31 && (size_t)page->chunk[i]^page->xorkey; ++i ){

	}
	if ( i == 32 ){
		puts("Too many chunks!");
		exit(-1);
	}
	page->chunk[i] = (char*)((size_t)p^page->xorkey);
	++sum;
	printf("Chunk index: %d\n",i);
}

void View(){
	printf("Please input chunk index:");
	int idx = read_int();
	if ( idx < 0 || idx > 31 ){
		puts("Invalid index!");
		exit(-1);
	}
	char * p = (char*)((size_t)page->chunk[idx]^page->xorkey);
	if ( p )
		printf("Content: %s\n", p);
	else
		puts("No such a chunk!");
}

void Delete(){
	printf("Please input chunk index: ");
	int idx = read_int();
	if ( idx < 0 || idx > 31 ){
		puts("Invalid index!");
		exit(-1);
	}
	char *p = (char*)((size_t)page->chunk[idx]^page->xorkey);
	if ( p )
	{
		--sum;
		free(p);
		page->chunk[idx] = (char*)(page->xorkey);
	}
}
int main(void){
	init();
	while(1){
		switch(menu_getinput()){
			case 1:{
				Allocate();
				break;
			}
			case 2:{
				View();
				break;
			}
			case 3:{
				Delete();
				break;
			}
			case 4:{
				puts("Bye!");
				exit(0);
			}
			default:{
				puts("Invaild choice!");
			}
		}
	}
	return 0;
}