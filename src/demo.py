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
    
#插入秘密信息
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
    


if __name__=="__main__":
    encrypted_msg=encrypt(raw_msg)
    addr=find_avaliable_addr(encrypted_msg)
    insert_msg(addr,encrypted_msg)