---
title: pwncollege - embryoio
date: 2022-06-15 17:11:23
categories: pwn learning
tags: pwncollege
---

前些日子在某知识星球了解到了pwn.college，ASU CSE466的课程网站。站内module简单且较成体系，希望刷完能有所得。第一章，emryoio从 5/15 断断续续做到 6/15 终于把142道都做完了。鉴于网站规则，不能上传具体的题解，主要记录一下知识点。

<!-- more -->

# level1-7 Basic

直接运行文件 

---

传参直接在文件名后接参数

---

`export` 设置环境变量

---

重定向输入（>）与输出 ( < )

---

`env -i` + 运行文件 忽略环境变量运行程序

# level8-14 shell脚本

编写shell脚本 

（`env -i` ）/ challenge/embryoio_level + 参数 （+ redirect ）

```shell
#!/bin/bash
exec -c /challenge/embryo* #直接将运行脚本的进程替换为运行challenge的进程 运行时的parent是shell脚本之上的interactive shell
env -i /challenge/embryo 
bash -c "exec -c /challenge/embryo"# 在sub shell运行“”内的指令
(
	exec -c /challenge/embryo*
) #在sub shell运行“”内的指令
 
```



# level15-21 ipython

**ipython** 直接执行shell命令 “ ！+指令” （**该情况python launch 一个shell用来launch process**）

```python
import subprocess
p=subprocess.Popen(["/challenge/embryoio_level"], stdout=subprocess.PIPE.stdin=subprocess.PIPE)
p.stdout.read()
```

```python
import pwn
p=pwn.process(["/challenge/embryoio_level"] + [参数], env={"环境变名":"值"}, stdout=pwn.PIPE.stdin=pwn.PIPE)
print (p.read().decode())
```

```python
import glob 
glob.glob("....")#需要一个参数用来指定匹配的路径字符串，其返回文件名只包括当前目录里的文件名。
```

```python
import pwn
with open("filename","w")as x:
    x.write("asdf")
p=pwn.process(["/challenge/embryoio_level"], stdout=open("filename","w"),stdin=open("fliename"))
#  redirect
```

```python
# os也能够对环境变量进行操作
import os
os.environ['name']="value" #设置环境变量
os.environ.get('name') #获取环境变量
os.getenv('path') #获取环境变量
del os.environ['name']
```

# level22-28 python脚本

同Ipython

**level27** 遇到 redirect 指定file 到stdout，文件未被写入的问题。通过查阅pwntools文档，使用**wait_for_close()**。

```python
from pwn import *
wait_for_close(timeout=pwnlib.timeout.Timeout.default)
wait(timeout=pwnlib.timeout.Timeout.default)
# Waits until the tube is closed.
# Python会先将数据临时存储到缓冲区中，只有使用 close() 函数关闭文件时，才会将缓冲区中的数据真正写入文件中。
```

# level29-35 C脚本

```c
#include <sys/wait.h>
#include <unistd.h>
 int main(int argc, char **argv)
{
    char *参数[]={"fliename",参数1,NULL}
    char *环境[]={"环境变量=值",NULL}
    int i = fork();		//fork creates a new child
    if (i == 0)		//execv replace the current process
    {
        execve(argv[1],NULL,NULL); //execl  
    }
    else
    {
        waitpid(i, NULL , 0)
    }
}
```



## main函数的参数

```c
int main(void)

int main(int argc,char *argv[])=int main(int argc,char **argv)
    1. int argc (arguments count 参数计数)
	 运行程序传送给main函数的命令行参数总个数，包括可执行文件的文件名，存储在argv[0]中
    2. char **argv (arguments value/vector 参数值)
	 argv[0]指向程序运行时的全路径名
	 argv[1]指向程序在DOS命令中执行程序名后的第一个字符串
	 argv[2]指向第二个字符串
	 argc[argc] 为NULL
```

## fork()

fork执行后有两次返回

1.  在父进程中，fork返回新创建子进程的进程ID；
2.  在子进程中，fork返回0；
3.  如果出现错误，fork返回一个负值；

## execve函数

```c
#include <unistd.h>
int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *path, const char *arg, ..., char *const envp[]);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execve(const char *path, char *const argv[], char *const envp[]);
//执行成功无返回；出错返回-1
```

## wait / waitpid

```c
include <sys/wait.h>
waitpid(pid_t pid ,int *status ,int options);
wait(int *status);
```

第一个参数为指定的子进程识别码，第二个参数用以了解子进程为什么会退出（不需要则为NULL），第三个为控制waitpid()的函数行为

当一个parent创建了一个child但没有等它结束就自己结束的话就可能造成系统异常，使用waitpid()来等待孩子进程。

| pid值 |             waitpid()的操作              |
| :---: | :--------------------------------------: |
|  -1   |              等待任一子进程              |
|  >0   |      等待其进程ID与pid相等的子进程       |
|  ==0  | 等待其组ID等于调用进程组ID的任一的子进程 |
|  <-1  |   等待其组ID等于pid绝对值的任一子进程    |

**wait函数为waitpid函数的简化版,wait返回任一终止状态的子进程，waitpid等待指定进程**

## open / close

```c
#include <sys/types.h>    #include <sys/stat.h>    #include <fcntl.h>
int open(const char *pathname ,int flags);
打开文件成功返回文件描述符（未使用的且为最小的fd）
打开文件失败返回 -1
```

- `flags`：用来控制打开文件的模式
  - `O_RDONLY`：只读模式
  - `O_WRONLY`：只写模式
  - `O_RDWR`：可读可写
  -  ......

- `mode`：用来设置创建文件的权限（rwx）。当flags中带有`O_CREAT`时才有效。

```c
#include <unistd.h>
int close(int fd)
返回值为0则关闭文件成功
返回值为-1则代表失败
```



### 文件描述符（*file descriptor*）

- 进程级 **文件描述符表(file descriptor table)**

  一般情况下，每个 Unix/Linux 命令运行时都会打开三个文件：

  - 标准输入文件(stdin)：stdin的文件描述符为0，Unix程序默认从stdin读取数据。
  - 标准输出文件(stdout)：stdout 的文件描述符为1，Unix程序默认向stdout输出数据。
  - 标准错误文件(stderr)：stderr的文件描述符为2，Unix程序会向stderr流中写入错误信息。

- 系统级 **打开文件表(open file table)**

- 文件系统 **i-node表( i-node table)**

![](/img/fd.png)

## dup和dup2

`dup()`或者`dup2()`主要是将某个特定的文件描述字输出输出的重定向
他们保证将复制的文件描述字到当前未打开的最小描述字

```c
#include<unistd.h>
int dup(int oldfd)
    参数oldfd表示需要复制的文件（必须已打开）的文件描述符
    返回值：若成功复制则返回一个新的文件描述符；若失败则返回-1
int dup2(int oldfd, int newfd);
```

**二者区别**

调用`dup(oldfd)`等效于，`fcntl(oldfd, F_DUPFD, 0)`
调用`dup2(oldfd, newfd)`等效于，`close(oldfd)；fcntl(oldfd, F_DUPFD, newfd)；`

### 重定向输入输出

```c
int dup2(int *oldfile ,STDIN_FILENO)
int dup2(int *oldfile ,STDOUT_FILENO)
```

**STDIN_FILENO 是标准输入的文件描述符**

## c脚本重定向输入

```c
//方法1
#include <stdio.h>
FILE *freopen(const char *filename, const char *mode, FILE *stream)
```

```c
//方法2
int main ()
{
   FILE *fp;
   printf("该文本重定向到 stdout\n");
   fp = freopen("file.txt", "w+", stdout);//创建一个用于读写的新文件
   printf("该文本重定向到 file.txt\n");
   fclose(fp);
   return(0);
}
```

# level36-65 PIPES

```typora
A pipe is a  form of redirection (transfer of standard output to some other destination)

 allow stdout of a command to be connected to stdin of another command

pipe character ' | '

Pipe is used to combine two or more commands, and in this, the output of one command acts as input to another command, and this command’s output may act as input to the next command and so on. 

Syntax:
command_1 | command_2 | command_3 | .... | command_N 
```

**send EOF = ctrl + D  ：close the program **

## python脚本的pipes

### pwntools

```python
import glob
import pwn
pwn.context.log_level = "DEBUG"
p2= pwn.process(["sed", "-e", "s/X/X/"], stdin=pwn.PIPE)
p1= pwn.process(glob.glob("/challenge/embryo*"), stdout=p2.stdin)
print(p2.readall())
```

### subprocess

```python
import subprocess
p1 = subprocess.Popen(["/challenge/embryoio_level"], stdout=subprocess.PIPE)
p2 = subprocess.Popen(["cat"], stdin=p1.stdout, stdout=subprocess.PIPE)
print(p2.communicate()[0].decode())
```

### level52

```python
In [14]: import pwn
#使用cat传入password
#或者使用sendline进行传递
```

### level59

这题使用subprocess时碰到了一些问题，主要是`Popen.communicate()`的使用

```python
Popen.communicate(input=None, timeout=None)
#与进程交互：将数据发送到 stdin。 从 stdout 和 stderr 读取数据，直到抵达文件结尾。
#本题中，若不加入communicate()函数，/challenge的parent变为docker-init
#原因为/challenge的parent已经结束，进而发生继承
#猜测原因，不使用communicate()，rev不会等待子进程，直接terminates
```

# C脚本的PIPEs

```c
#include <unistd.h>
int pipe( int pipe_fds[2] )  
//return 成功返回0，否则返回-1。参数数组包含pipe是用的两个文件的描述符。
//fd[0]为read管道 fd[1]为write管道
//必须在fork中调用pipe()否则子进程不会继承文件描述符。两个进程不共享parent进程就不能使用pipe。
```

c pipes具体实现

```c
#include <unistd.h>
#include <sys/wait.h>
int main()
{
        int pid=fork();
        if (pid == 0)
        {
                int pipe_fd[2];
                pipe(pipe_fd);
                int i =fork();
                if (i!=0)
                {
                        dup2(pipe_fd[1],1);
                        execve("/challenge/embryoio_level",NULL,NULL);
                }
                else
                {
                        dup2(pipe_fd[0],0);
                        execl("/bin/cat","/bin/cat",NULL);
                }
        }
        else
        {
                waitpid(pid,NULL,0);
        }
}
```

# level61-68 find指令

```shell
find /challenge/ -name embryoio_level66 -exec {} ;
```

# level68-73 shell脚本杂项

**使用c进行辅助更方便些**

# level74-79 python脚本杂项

```python
from pwn import *
p = process(argv = [], executable = "/challenge/embryoio_level75")
p.interactive() #设置参数为空
```

# level80-85 c脚本杂项

```c
#inlcude <unistd.h>
chdir(path);
//change the current working directory
```

# level86-98 shell脚本杂项2

## level86-87 interaction

写了个脚本自动交互，恰好后面也用的上

## level88-89 argv[0]

```shell
argv[0] is passed into the execve() system call *separately* from the program path to execute.This means that it does not have to be the same as the program path, and that you can actually control it. This is done differently for different methods of execution. For example, in C, you simply need to pass in a different argv[0]. Bash has several ways to do it, but one way is to use a combination of a symbolic link (e.g., the `ln -s` command) and the PATH environment variable.
```

**设定PATH环境变量**

`$PATH`：输入命令时，系统通过查找PATH中的路径来执行具体文件。各个目录用`:`分割开

**command**

- which -- 查找各个外部指令所在的绝对路径
- export -- 修改环境变量（临时）

## level90-93 FIFO

**FIFO - named pipe**

```typora
有名管道 FIFO 和无名管道 Pipe 主要的区别就是 FIFO 在磁盘上建立管道文件（FIFO 将内核数据缓冲区映射到了实际的文件节点），所以我们可以在磁盘上实际看到，故称为「有名字」，而 Pipe 没有在磁盘上建立文件，我们不能实际看到，故称为「无名」
我们使用 FIFO 是在磁盘上建立一个管道文件，然后利用这个文件作为管道的传输通道，但是这个管道文件很特殊，它的大小始终为 0，原因是管道的数据是存放在内核的内存中的，不在管道文件中，我们也可以验证这个事实。
```

向管道写数据必须用`>`，从管道读数据时必须用`<`。还有一点是写管道的时候必须要用`&`把进程挂到后台 / 或者在两个终端进行交互

```shell
mkfifo fifo_flie
```

```c
int mkfifo(const char *pathname, mode_t mode);
```

## level94 exec重定向

```shell
exec fd_num < filename #打开文件作为当前shell的输入，并分配文件描述符
```

## level97-98 信号

使用`kill -signum pid`可以发送指定的信号给指定的进程。

# level99-111 python杂项2

重复86-98的工作

# level112-124 c杂项2

重复86-98的工作

# level125-139 脚本编写

均使用pwntools编写，计算依靠eval()实现，发送信号由os.kill实现

令程序的stdin,stdout都由cat来连接时，pwntools的pipe似乎不怎么好用(?)，使用os.pipe实现

# level140 Webserver

## shell

在 Linux 中有这样一个特殊文件 `/dev/{tcp|udp}/${host}/${port}`，打开这个文件，就相当于发出了一个 socket 调用，建立了一个 socket 连接，读写这个文件就相当于在该 socket 连接中传输数据。

`/dev/{tcp|udp}/${host}/${port}`不是一个真实的文件，且仅存在于bash，其他的shell如sh、dash、zsh中是没有的。

```shell
$ exec 9<> /dev/tcp/www.baidu.com/80
在当前 shell 中创建一个文件描述符 9，该文件描述符的输入和输出都重定向到/dev/tcp/www.baidu.com/80
```

```shell
while read -u 3 LINE;do #从fd3读取并输出
        echo $LINE
        line1=$LINE
        echo 1 >&3 #输出到指定fd
done
```



## python

直接使用 pwntools 的 remote

## c

c语言socket programming (TCP)

https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/

https://www.geeksforgeeks.org/socket-programming-cc/
