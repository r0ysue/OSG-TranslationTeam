# macOS 10.12.2本地提权和XNU port堆风水

## 0x00 简介
从yalu 10.2，我们可以学到很多新的漏洞利用技术，特别是XNU堆风水和绕过内核保护。 在本文中，我们将讨论XNU堆风水的技术细节，并通过该技术使macOS获得root权限。最后但并不是最重要的，漏洞源码可以从以下网址下载：
[https://github.com/zhengmin1989/macOS-10.12.2-Exp-via-mach_voucher](https://github.com/zhengmin1989/macOS-10.12.2-Exp-via-mach_voucher)

## 0x01 内核堆栈溢出
通过XNU堆风水在macOS 10.12中获得root权限，我们需要一个内核漏洞。在本文中，我们选择`mach_voucher`堆溢出作为例子，`Mach_voucher_extract_attr_recipe_trap()`是可以在沙箱内调用的Mach陷阱，这是在iOS 10和macOS 10.12中添加的新功能，但是他有一个可怕的缓冲区溢出漏洞。

![d71rt073i56.png](http://oh5mz2415.bkt.clouddn.com/d71rt073i56.png)

在函数中，`args->recipe_size`是一个指向整数的用户态指针，所以`mach_voucher_extract_attr_recipe_trap()`通过`copyin()`将size的值从用户态拷贝到内核， 然后赋值给sz.

![446in89rqbm0.png](http://oh5mz2415.bkt.clouddn.com/446in89rqbm0.png)

该函数然后使用sz值在内核堆上分配一个内存块。但是，开发人员忘记了args-> recipe_size是一个用户态指针，于是使它在`copyin()`中作为一个值， 我们知道用户态指针可能大于sz值，这将导致内核堆中的缓冲区溢出。

需要注意的是，如果我们要在该地址上分配一个内存块，我们可能无法控制用户态指针的地址。但这不是问题。如果遇到未映射的内存，`copyin（）`函数会自动停止。 因此，我们可以在高地址上分配一个内存块，然后取消映射其余的内存块来控制溢出数据。

![446ina2jpor0.png](http://oh5mz2415.bkt.clouddn.com/446ina2jpor0.png)

## 0x02 通过port进行堆风水

在iOS 10和macOS 10.12中，苹果添加了一个新的缓解机制，以检查是否释放了错误的区域攻击，因此我们无法使用经典的`vm_map_copy`（更改`vm_map_size`）技术来执行堆风水。

此外，苹果在iOS 9.2和macOS 10.11中添加了一个free list随机化机制，我们不能轻易地预
测重新分配的内存块的位置。 为了解决这些问题，我们需要一个新的堆风水技术。

在Yalu 10.2中，`qwertyoruiop`使用`OOL_PORTS`获取可用于执行任意内核内存读写的内核任务端口。 这种技术绕过了XNU堆中的所有缓解机制。在本节的其余部分，我们将讨论这种技术的细节。

`Mach msg`是XNU中最常用的IPC机制，大量消息通过“复杂的消息”发送。通过`MACH_MSG_OOL_PORTS_DESCRIPTOR msg_type`的“复杂消息”，我们可以向内核发送out-of-line端口。例如，我们发送了32个`MACH_PORT_DEAD` ool端口（32 * 8字节=0x100字节）到内核的kalloc.256区域。

![42423423.png](http://oh5mz2415.bkt.clouddn.com/42423423.png)

保存在mach msg中的ool端口是`ipc_object`指针，指针可以指向用户态地址。 因此，我们可以使用`mach_voucher`漏洞来溢出这些指针，并在用户态下修改一个`ipc_object`指针用来指向一个伪造的`ipc_object`。 另外，我们也可以在用户态伪造的fake port下创建一个fake task。

![31231313.png](http://oh5mz2415.bkt.clouddn.com/31231313.png)

为了保证溢出正确的`ipc_object`指针，我们需要做一些堆风水。 首先，我们向内核发送大量的ool端口消息，以确保新分配的内存块是连续的。 然后我们在中间收到一些消息来挖掘一些槽。 然后我们再次发送一些消息，使溢出点在槽的中间。 最后，我们使用`mach_voucher`在溢出点触发堆溢出。

![446ip2ru4i90.png](http://oh5mz2415.bkt.clouddn.com/446ip2ru4i90.png)

溢出之后，我们可以收到其他mach消息，以找到损坏的端口（不是`MACH_PORT_DEAD`端口）。
![446ip41tfpa0.png](http://oh5mz2415.bkt.clouddn.com/446ip41tfpa0.png)

## 0x03 内核内存任意读写

首先，我们将伪造的`ipc_object`的`io_bits`设置为`IKOT_CLOCK`。所以我们可以使用`clock_sleep_trap（）`遍历内核来获取内核中`clock_task`的地址。 这个地址将帮助我们稍后找到内核数据。

![446ipedl1v50.png](http://oh5mz2415.bkt.clouddn.com/446ipedl1v50.png)

然后我们将伪造的`ipc_object`的`io_bits`设置为`IKOT_TASK`，将fakeport的task指向伪造的faketask。 通过将值设置为faketask + 0x380（在arm64中为0x360），我们可以通过`pid_for_task（）`读取任意32位内核内存。 这是令人吃惊的，因为该函数不检查task的有效性，只返回*（*（faketask + 0x380）+ 0x10）的值。 所以我们可以在没有任何小工具和ROP的情况下获得可靠性内核读取。

![446ipg2vp590.png](http://oh5mz2415.bkt.clouddn.com/446ipg2vp590.png)
![446iph1n7mf0.png](http://oh5mz2415.bkt.clouddn.com/446iph1n7mf0.png)

通过`clock task`泄露的内核地址，我们可以在内存中搜索内核镜像的魔数，找到kslide。

![446ipi9j31o0.png](http://oh5mz2415.bkt.clouddn.com/446ipi9j31o0.png)

获取内核基础后，我们可以遍历所有进程来查找内核`ipc_object`和内核任务。然后我们可以`dump`出来内核的`ipc_object`以及内核进程的task数据并赋值给fake port。通过对我们的伪造的`ipc_object`和task使用`task_get_special_port（）`，我们可以获得内核任务端口。值得注意的是，内核任务端口非常强大。它可以用于通过`mach_vm_read（`）和`mach_vm_write（）`进行任意内核内存读写。

![446ipjo49820.png](http://oh5mz2415.bkt.clouddn.com/446ipjo49820.png)

## 0x04 root提权

每个进程的凭据信息，`posix_cred`结构存储在内核内存中。我们首先需要找到我们的进程信息（从内核base + allproc），然后找到我们的exploit进程的`posix_cred`结构数据。 之后，我们通过`kernel_task_port`使用`mach_vm_write（`）将`cr_ruid`（实际用户ID）值设置为0（这意味着将进程的uid变成了root）。最后但并不是最重要的是，我们可以使用system（“/ bin / bash”）获取根shell！

![446ipm366tr0.png](http://oh5mz2415.bkt.clouddn.com/446ipm366tr0.png)

## 0x05 摘要 

在本文中，我们介绍了如何使用`mach_voucher`堆溢出和堆风水来实现macOS 10.12.2上的本地提权。漏洞源码可以从以下网址下载：

[https://github.com/zhengmin1989/macOS-10.12.2-Exp-via-mach_voucher](https://github.com/zhengmin1989/macOS-10.12.2-Exp-via-mach_voucher)

## 0x06 参考

1. Yalu 102: [https://github.com/kpwn/yalu102](https://github.com/kpwn/yalu102)
2. [https://bugs.chromium.org/p/project-zero/issues/detail?id=1004](https://bugs.chromium.org/p/project-zero/issues/detail?id=1004)