# Helper functions to easily convert between integers and bytes

def bytes_to_list(bytesrep):
    return list(bytesrep)

def list_to_bytes(lisrep):
    return bytes(lisrep)

def bytes_to_int(by):
    li=bytes_to_list(by)
    val=0
    for j in li:
        val=256*val+j
    return val

def int_to_bytes(int_val):
    li=[]
    while int_val != 0:
        li = [int_val%256]+li
        int_val=int_val//256
    return list_to_bytes(li)


    



    
    
