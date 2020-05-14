---
title: 一种基于PE文件的信息隐藏方法的研究与实现（信息隐藏相关）
categories: 随想
---
# 研读文献————一种基于PE文件的信息隐藏方法的研究与实现（信息隐藏相关）

## 研究原因

目前在信息隐藏方面研究最深入成果最丰富的是基于图像的信息隐藏技术而对文本图形动画视频等其他多媒体中的信息隐藏技术研究得还比较少。PE文件是当前最常见的文件之一，使用范围非常广泛因而研究基于Windows下PE文件的信息隐藏有很大的实际意义。

## PE文件结构解析

在一个操作系统中，可执行代码在装入内存前是以文件的方式存储在磁盘上，而在装入内存时需要被程序装载器识别才能正常执行因而需要可执行文件满足特定的格式。在Windows NT6.X系列操作系统中，纯32位操作系统使用PE格式(Portable Executable File Format)。

在Windows系统中EXE和DLL都是PE文件两者惟一的区别是用一个字段来标识。另外在64位的Windows中. PE文件中的数据字段只是简单的扩展到64位与32位系统相比没有新的结构。论文主要讨论32位PE可执行文件。

PE文件格式把可执行文件分成若干个数据节（section），不同的资源被存放在不同的节中。
一个典型的PE 文件中包含的节如下：

* .text 由编译器产生，存放着二进制的机器代码，也是我们反汇编和调试的对象。
* .data 初始化的数据块，如宏定义、全局变量、静态变量等。
* .idata 可执行文件所使用的动态链接库等外来函数与文件的信息。
* .rsrc 存放程序的资源，如图标、菜单等。

除此以外，还可能出现的节包括“.reloc”、“.edata”、“.tls”、“.rdata”等。

## PE文件与虚拟内存之间的映射

在默认情况下，32位系统中，一般PE 文件的0 字节将对映到虚拟内存的0x00400000位置（未开启全局ASLR），这个地址就是所谓的装载基址(Image Base)，映射完成的地址称为VA（虚拟内存地址）。

文件偏移是相对于文件开始处0 字节的偏移，RVA（相对虚拟地址）则是相对于装载基址0x00400000 处的偏移。由于操作系统在进行装载时“基本”上保持PE 中的各种数据结构，所以文件偏移地址和RVA 有很大的一致性。

RVA与文件偏移地址的差异是由于文件数据的存放单位与内存数据存放单位不同而造成的。

1. PE 文件中的数据按照磁盘数据标准存放，以0x200 字节为基本单位进行组织。当一个数据节（section）不足0x200 字节时，不足的地方将被0x00 填充；当一个数据节超过0x200字节时，下一个0x200 块将分配给这个节使用。因此PE 数据节的大小永远是0x200 的整数倍。
2. 当代码装入内存后，将按照内存数据标准存放，并以0x1000 字节为基本单位进行组织。类似的，不足将被补全，若超出将分配下一个0x1000 为其所用。因此，内存中的节总是0x1000 的整数倍。

文件偏移地址 = 虚拟内存地址（VA）−装载基址（Image Base）−节偏移 = RVA -节偏移

## PE文件冗余空间分析

1. PE文件的结构本身的冗余；
2. RVA与文件偏移地址差异的冗余；
3. 人为制造一个新的节来存放隐藏的信息；

针对（2），实则就是在内存中大量的'\x00'的空间内存放秘密数据，这样不会破坏原有程序的完整性。


## 实现方案

论文使用的是mfc，基于WINNT.H这个头文件解析PE文件的，实际实现使用了Python的pefile库解析PE文件。

简单Demo代码，实现了分批次的存储：

encrypt:

```python
#coding=utf-8
import pefile
import binascii
import rsa

pe_path=".\\fortest_patch.exe"
pe=pefile.PE(pe_path)

raw_msg="hello,how old are you"

#加密
def encrypt(m):
    (pubkey, privkey) = rsa.newkeys(1024)
    
    with open('public.pem','w+') as f:
        f.write(pubkey.save_pkcs1().decode())
    with open('private.pem','w+') as f:
        f.write(privkey.save_pkcs1().decode())

    c = rsa.encrypt(m.encode(), pubkey)

    return c


#找到某个段中可以存放秘密的空间
def find_avaliable_addr(msg):

    for section in pe.sections:

        #print (section.Name, hex(section.VirtualAddress))

        if section.Name==b'.data\x00\x00\x00':
            data_rva=section.VirtualAddress
            print("find avaliable address blow .data address:",hex(data_rva))
            section.Misc_VirtualSize=section.Misc_VirtualSize+128
            print("chang section's virtualSize to: ",hex(section.Misc_VirtualSize))
    
    print("msg length is: ",len(msg))
    addr=data_rva-len(msg)
    for i in range(len(msg)):
        if pe.get_data(addr+i,1)!=b'\x00':
            print("please find another section!")
            return -1

    print("address ",hex(addr),"is avaliable!")
    return addr
    
#插入秘密信息到单一段
def insert_msg(addr,msg):
    if addr!=-1:
        index=0

        for cur_str in msg:
            pe.set_dword_at_rva(addr+index,cur_str)
            index=index+1
            

        print("inset data: ",binascii.b2a_hex(pe.get_data(addr,len(msg))))

        pe.write(filename='.\\file_to_write1.exe')
    else:
        print("address is not valid")
    

#找出存放拆分开的秘密信息的地址
def find_avaliable_addr2(msg):
    msg1=msg[:64]
    msg2=msg[64:]

    for section in pe.sections:
        if section.Name==b'.data\x00\x00\x00':    
            data1_rva=section.VirtualAddress-64
            print("find avaliable address blow .data address:",hex(data1_rva))
        
        if section.Name==b'.rdata\x00\x00':    
            data2_rva=section.VirtualAddress-64
            print("find avaliable address blow .text address:",hex(data2_rva))

    return [data1_rva,data2_rva]

#插入秘密信息到多个段
def insert_msg2(addr1,addr2,msg):
    msg1=msg[:64]
    msg2=msg[64:]

    #塞msg1
    index1=0
    for char1 in msg1:
        pe.set_dword_at_rva(addr1+index1,char1)
        index1+=1

     #塞msg2
    index2=0
    for char2 in msg2:
        pe.set_dword_at_rva(addr2+index2,char2)
        index2+=1

    print("insert data into .data & .rdata")
    pe.write(filename='.\\file_to_write2.exe')


def test1():
    encrypted_msg=encrypt(raw_msg)
    
    #嵌入到单一段
    addr=find_avaliable_addr(encrypted_msg)
    insert_msg(addr,encrypted_msg)

def test2():
    encrypted_msg=encrypt(raw_msg)

    #嵌入到多个段
    addr=find_avaliable_addr2(encrypted_msg)
    addr1=addr[0]
    addr2=addr[1]
    insert_msg2(addr1,addr2,encrypted_msg)

if __name__=="__main__":
    #test1()
    test2()
```

decrypt:

```python
#coding=utf-8
import pefile
import binascii
import rsa

pe_path=".\\file_to_write2.exe"
pe=pefile.PE(pe_path)
msg_length=128

with open('private.pem','r') as f:
    privkey = rsa.PrivateKey.load_pkcs1(f.read().encode())


def get_addr():
    for section in pe.sections:
        if section.Name==b'.data\x00\x00\x00':
            data_addr=section.VirtualAddress-128
            return data_addr
    return -1

def get_addr2():
    for section in pe.sections:
        if section.Name==b'.data\x00\x00\x00':
            data_addr1=section.VirtualAddress-64
            
        if section.Name==b'.rdata\x00\x00':
            data_addr2=section.VirtualAddress-64

    return [data_addr1,data_addr2]

def detest1():
    addr=get_addr()

    msg=pe.get_data(addr,msg_length)

    message = rsa.decrypt(msg, privkey).decode()

    print("inseted data: ",message)


def detest2():
    addr1=get_addr2()[0]
    addr2=get_addr2()[1]

    print("data1:",hex(addr1))
    print("data2",hex(addr2))
    data1=pe.get_data(addr1,64)
    data2=pe.get_data(addr2,64)
    data=data1+data2
    message = rsa.decrypt(data, privkey).decode()
    print("inseted data: ",message)

if __name__=="__main__":

    detest2()
```