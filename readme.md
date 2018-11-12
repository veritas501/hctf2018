# HCTF 2018 (part)

[TOC]

---



这是我第二次参与HCTF的出题和策划，这次一共出了4道题,如下。

详细见文件，下面是简要思路解释。

## Pwn - the end （46 solves）

这题本意是作为签到题，看下来效果也的确不错。

程序给你5次任意地址写1byte的机会，然后马上exit。那么问题很明显，肯定是要怼exit了。

因为程序是FULL RELRO的，所以打linkmap的方法就无法生效了（hack.lu ctf slot_machine）

仔细跟踪exit，能够控制程序流的地方有两处，一处是tls，一处是IO_FILE。



tls处5bytes大概是搞不定了，所以我们可以看一下IO_FILE。

在IO_FILE的调用中，用到了stdout的vtable。由于题目使用了2.23的libc，因此我先用2byte改vtable到libc got表附近，让call vtable[idx]正好跳到realloc.got，我们用剩下的3byte改realloc_hook中的初始值到one_gadget，就能getshell。



由于close了stdout和stderr，其实我们可以`cat flag 1>&0`。stdin也是可以用来输出的。

## Pwn - heapstorm zero（3 solves）

只有3解比较意外，我本意是作为中等题的。

这题来源于我对null off by one的思考，理论上来说，null off by one 打在fastbin上是不可能被利用的，因为size位直接变成了0。那如何让选手在只能分配fastbin的同时利用null off by one呢？



只能藏一个比较不明显的分配大堆块的行为了。这个行为由scanf来做到。虽然我setvbuf了，输入超长字符串的时候scanf还是会在堆上分配buffer来暂存我们的输入。最小分配size也是0x400，也就是一个large chunk了。这样我们就有了触发malloc consolidate的能力，将多个fastbin融合成一个unsorted bin，然后利用null off by one，就能在堆上搞事了。

接下来就是overlap heap等一系列冗长的利用，因为使用了calloc，构造起来还是比较复杂的，这里就不细说了。



之后我是leak了libc，造出了fastbin dup，然后利用fd在main arena上留一个size，然后fastbin attack打过去，利用这个堆块就可以在main arena的fastbin list上写东西，部分控制fastbin list以后我们可以最终改到top chunk指针，指到malloc hook前，然后改malloc hook到onegadget，通过再次malloc成功get shell。



当然我也看到了其他选手的流量，有选手是通过orange做的，当然也是可以的。

## Pwn - christmas（4 solves）

这题出了一点点的小意外，我本来是当作pwn压轴出的，因为我当时想搜amd64的alphanumeric shellcode encoder，并没有看到alpha3这个神器，所以打算将编写encoder作为题目的一部分（然而选手都比我聪明，找到了现成的encoder，因此题目难度大幅降低 orz orz orz。

any way，还是说一下我的思路。

先不说shellcode上的限制。选手需要在只能用exit或loop做盲测的情况下找到一个未知的lib中的一个函数的位置，调用它，并测出flag。



找lib的方法大致有两种。

1.可以在got上摸到linkmap地址（因为没有pie和full relro），利用linkmap上的`l_next`我们可以一个个linkmap摸过去，直到找到libflag的。得到基地址后我们可以通过header上的信息得到strtab和symtab的位置，然后通过字符串比较手动解析`flag_yes_1337`函数的位置。（我和其他队伍做法）

2.因为程序没有pie，我们可以在got等地方get libc的地址，通过偏移算出`libc_dlsym`，然后调用这个函数解析`flag_yes_1337`所在位置。（Nu1L）

之后，调用`flag_yes_1337`，flag字符串来到rax，然后盲测每一bit得到flag。



现在问题就来到了如何将我们shellcode encode成alphanumeric 。

方法还是有两种：

1.在网上找到alpha3 encoder，魔改后直接使用。（所有队伍做法）

2.自己写一个encoder。



得知他们都是用alpha3以后，我也去读了一下alpha3的做法。通过比较我也发现我的encoder还是离大佬写的差了很多。

不过出于学习，我也在此介绍一下我写encoder的思路。



encode无非是xor，或一层，直接用解密真实shellcode；或两层，先解密一个精致的encoder，这个encoder再去解密真实的shellcode。

我采用了一层的做法，这样做的缺点就是encode后shellcode长度会膨胀很厉害。

如何xor指定offset的一个byte？？

```
xor [rax+rdi],dl
xor [rax+rdi],dh
xor [rax+rdi+0x32],dl
xor [rax+rdi+0x32],dh
```

这些都是比较好的gadget。那问题就到了如何设置rdi上。

```
push XXX
push rsp
pop rcx
imul edi,[rcx],YYY
```

因为imul的对象是edi，因此可以将最高位溢出，得到一个几乎任意的edi值，但是XXX和YYY除都必须是alphanumeric，这个问题不大，我做了打表处理。

举个例子，我们要xor idx为80处的byte，可以通过一下代码实现。

```
push 1431655766
push rsp
pop rcx
imul edi,[rcx],48
xor [rax+rdi+48],dl
```

idx的问题解决了，就是怎么合理设置dl或dh的值让所有byte xor或不xor后，结果都落在alphanumeric范围中。

我用脚本跑了一下，0x80~0xff的字符最少需要4个不同的值才能全部xor到alphanumeric，而0x00~0x7f只需要3个不同的值。

比如我们取 0x30，0x59，0x55来xor 0x00到0x7f，取0x80，0xc0，0x88，0xc8来xor 0x80到0xff，分别放到dh和dl，就有了下面4个int，这几个值都能通过上面设置idx的方法得到。

```
r8  : 0x3080
r9  : 0x59c0
r10 : 0x5988
rdx : 0x55c8
```

这样无论遇到什么byte，我们都能通过这个方法xor了 。 nice~

## Misc - eazy dump（25 solves）

出这题其实不是我本意，完全是因为misc出题人太摸了我看不下去，无奈只能帮他出一题。题目定位是娱乐难度。



主要考点是用过gimp来讲内存视为 raw 图片来看内存中的贴图，flag画在mspaint上。网上也有类似了，不细说了。

