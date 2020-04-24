#!/usr/bin/env python3
import math
import sys,argparse

parser=argparse.ArgumentParser()

parser.add_argument("--number","-n",required=True,help="Number to factorize|N-th prime to calculate",type=int)
parser.add_argument("--prime","-p",help="Calculate the -n N-th prime",type=bool,default=False)
args=parser.parse_args(sys.argv[1:])

n=args.number
justPrime=args.prime

pi=[2]

def addPrime(pl):
    np=pl[len(pl)-1]+1
    while(1):
        upper=(math.isqrt(np)+1)
        fail=False
        for p in pl:
            if np%p==0:
                fail=True
                break
            if p>upper:
                break
        if fail==False:
            pl.append(np)
            return pl
        np+=1
    
def factorize(num,pl):
    f=pl[len(pl)-1]
    upper=(math.isqrt(num)+1)
    while f<upper:
        print(f"bits: {int(math.log2(f))+1}   f: {f}    {f/upper*100:0.4f}%                  ",end="\r",flush=True)
        f=pl[len(pl)-1]
        if num%f==0:
            print()
            print(f"found a new factor: {f}")
            return [f]+factorize(num//f,pl)
        pl=addPrime(pl)
    return [num]

if justPrime==False:
    print(factorize(n,pi))
else:
    while(len(pi)<n):
        addPrime(pi)
        print(f"{len(pi)/n*100:0.4f}%",end="\r",flush=True)
    print()
    print(pi[len(pi)-1])