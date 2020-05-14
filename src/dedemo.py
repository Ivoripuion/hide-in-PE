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