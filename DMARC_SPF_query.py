#!/usr/bin/env python
# coding: utf-8

# sudo pip3 install dnspython
# 
# sudo pip3 install ipwhois


import dns.resolver
import socket
from ipwhois import IPWhois
from pprint import pprint
import json
import csv

lookup = 0
ip = {}

def check_spf(domain,pad):
    global lookup, ip
    lookup += 1
    print(('   ' * pad) + domain)
    answers = dns.resolver.query(domain, 'TXT')
    for rdata in answers:
        r = rdata.to_text().replace('"','')
        if ('v=spf1' in r):
            print(('   ' * pad) + r)
            print('   ' * pad)
            s = r.split(' ')
            for x in s:
                if(x[:4] == 'ip4:' or x[:4] == 'ip6:'):
                    ip[x] = domain
                if(x[:8] == 'include:'):
                    check(x.replace('include:',''),pad+1)
    
def check_dmarc(domain):
    global lookup, ip
    domain_check= "_dmarc."+domain
    answers = dns.resolver.query(domain_check, 'TXT')
    for rdata in answers:
        r = rdata.to_text().replace('"','')
        if ('v=DMARC1' in r):
            print(r)
            x = dict(item.split("=") for item in r.split(";"))
            print(json.dumps(x, indent=1))
            #print("v =",x["v"])
            #print("p =",x["p"])
            #print("pct =",x["pct"])
            #print("fo =",x["fo"])
            #print("ri =",x["ri"])
            #print("rua =",x["rua"])
            #print("ruf =",x["ruf"])


def who(i,v):
    print(i + ' -> ' + v)
    i = i.replace('ip4:','').replace('ip6:','')
    p = i.split('/')
    obj = IPWhois(p[0])
    results = obj.lookup_rdap(depth=1)
    print('Network Name : ' + results['network']['name'])
    print('ASN Desc     : ' + results['asn_description'])
    first = next(iter(results['objects'].values()))
    print('Contact Name : ' + first['contact']['name'])



if __name__ == '__main__':
    domain = "easysol.net"
    try:
        print('DMARC Policy')
        print()
        check_dmarc(domain)
        print("-----------")
        print('SPF Chain')
        print()
        check_spf(domain,0)
    except:
        print("Record Error")
    print('Total lookups: ' + str(lookup))
    print('')
    #print('IP Ownership Info')
    #for key, value in ip.items():
    #  who(key,value)





