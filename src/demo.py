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
    
    test2()