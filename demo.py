def print_fseries(n):
    n0=0
    n1=1
    i=1
    num=[]
    num.append(n0)
    num.append(n1)
    nn=0
    while (1):
        nn=n0+n1
        n0=n1
        n1=nn
        if nn<n:
            num.append(nn)
        else:
            break
    return num

print(print_fseries(100))
