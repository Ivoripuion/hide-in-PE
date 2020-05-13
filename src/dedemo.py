#coding=utf-8
import pefile
import binascii
import rsa

pe_path=".\\file_to_write1.exe"
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
            
if __name__=="__main__":

    addr=get_addr()

    msg=pe.get_data(addr,msg_length)

    message = rsa.decrypt(msg, privkey).decode()

    print("inseted data: ",message)

