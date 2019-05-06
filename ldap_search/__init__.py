#!/usr/bin/env python

# Author: m8r0wn
# License: GPL-3.0

import argparse
from os import path
from sys import exit
from getpass import getpass
from datetime import datetime
from socket import gethostbyname
from ldap_search.core import LdapEnum

##################################################
# Fancy print statements
##################################################
def print_success(msg):
    print('\033[1;32m[+] \033[1;m{}'.format(msg))

def print_status(msg):
    print('\033[1;34m[*] \033[1;m{}'.format(msg))

def print_failure(msg):
    print('\033[1;31m[-] \033[1;m{}'.format(msg))

def print_error(msg):
    print('\033[1;33m[!] \033[1;m{}'.format(msg))

##################################################
# Resolve Domain/server name
##################################################
def resolve_host(domain):
    try:
        return gethostbyname(domain)
    except:
        return "n/a"

##################################################
# Argparse support functions
##################################################
def parse_attrs(attrs):
    if not attrs:
        return []
    else:
        return attrs.split(",")

def file_exists(parser, filename):
    # Verify input files exists
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    return [x.strip() for x in open(filename)]

##################################################
# Display/Format Query Data
##################################################
def print_keyValue(k,v):
    print(k)
    for x, y in v.items():
        print("    {:<20} {}".format(x, y))

def format_data(resp, lookup_type, query, attrs, resolve, verbose):
    for k, v in resp.items():
        if resolve:
            k = k + " - " + resolve_host(k)

        if verbose:
            print_keyValue(k,v)
        elif attrs:
            print_keyValue(k, v)
        elif lookup_type in ['user', 'users'] and query:
            print_keyValue(k,v)
        elif lookup_type in ['domain', 'trust']:
            print_keyValue(k, v)
        elif query == 'eol':
            print("{}\t - {}".format(k,v['operatingSystem']))
        else:
            print(k)

##################################################
# Launch Query
##################################################
def launcher(args):
    run_query = True
    start = datetime.now()
    data_len = 0
    for user in args.user:
        for passwd in args.passwd:
            try:
                if not args.srv:
                    args.srv = resolve_host(args.domain)
                query = LdapEnum(user, passwd, args.hash, args.domain, args.srv, args.timeout)
                print_success("Ldap Connection - {}:{}@{} (Domain: {}) (LDAPS: {})".format(user, passwd, args.srv, args.domain,query.ldaps))
                # Only run query once, then continue to check login status
                if run_query:
                    # Users
                    if args.lookup_type in ['user', 'users']:
                        resp = query.user_query(args.query, args.attrs)

                    # Groups
                    elif args.lookup_type in ['group', 'groups']:
                        if args.query:
                            resp = query.group_membership(args.query, args.attrs)
                        else:
                            resp = query.group_query(args.attrs)

                    # Computers
                    elif args.lookup_type in ['computer', 'computers']:
                        resp = query.computer_query(args.query, args.attrs)

                    # Domain
                    elif args.lookup_type == 'domain':
                        resp = query.domain_query(args.attrs)

                    # Trust
                    elif args.lookup_type == 'trust':
                        resp = query.trust_query(args.attrs)

                    # Custom
                    elif args.lookup_type == 'custom':
                        resp = query.custom_query(args.query, args.attrs)

                    else:
                        raise Exception('[!] Incorrect query statement.')

                    # Display results
                    if args.lookup_type and resp:
                        format_data(resp, args.lookup_type, args.query, args.attrs, args.resolve, args.verbose)
                        run_query = False
                data_len = len(query.data)
                query.close()
            except Exception as e:
                if "ACCOUNT_LOCKED_OUT" in str(e):
                    print_failure("Account Locked Out - {}:{}@{}".format(user, passwd, args.srv))
                elif args.debug:
                    print_error("Error - {}".format(str(e)))
    print_status("Fetched {} results in {}\n".format(data_len, datetime.now() - start))

##################################################
# Main
##################################################
def main():
    version = '0.1.0'
    args = argparse.ArgumentParser(description="""
               ldap_search (v{0})
--------------------------------------------------
Perform LDAP search queries to enumerate Active Directory environments.

Usage:
    python3 ldap_search group -q "Domain Admins" -u user1 -p Password1 -d demo.local
    python3 ldap_search users -q active -u admin -p Welcome1 -d demo.local 
    """.format(version), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    # Main Ldap query type
    args.add_argument('lookup_type', nargs='?', help='Lookup Types: user, group, computer')
    args.add_argument('-q', dest='query', type=str, default='', help='Specify user or group to query')
    args.add_argument('-a', dest='attrs', type=str, default='', help='Specify attrs to query')

    # Domain Authentication
    user = args.add_mutually_exclusive_group(required=True)
    user.add_argument('-u', dest='user', type=str, action='append', help='Single username')
    user.add_argument('-U', dest='user', default=False, type=lambda x: file_exists(args, x), help='Users.txt file')

    passwd = args.add_mutually_exclusive_group()
    passwd.add_argument('-p', dest='passwd', action='append', default=[], help='Single password')
    passwd.add_argument('-P', dest='passwd', default=False, type=lambda x: file_exists(args, x),
                        help='Password.txt file')
    passwd.add_argument('-H', dest='hash', type=str, default='', help='Use Hash for Authentication')

    args.add_argument('-d', dest='domain', type=str, default='', required=True, help='Domain (Ex. demo.local)')
    args.add_argument('-s', '-srv', dest='srv', type=str, default='', help='LDAP Server (optional)')
    args.add_argument('-r', dest="resolve", action='store_true', help="Use DNS to resolve records")

    # Alt program arguments
    args.add_argument('-t', dest='timeout', type=int, default=3, help='Connection Timeout (Default: 4)')
    args.add_argument('-v', dest="verbose", action='store_true', help="Show attribute fields and values")
    args.add_argument('-vv', dest="debug", action='store_true', help="Show connection attempts and errors")
    args = args.parse_args()

    if args.debug:
        args.verbose = True

    args.attrs = parse_attrs(args.attrs)

    if args.hash:
        args.passwd.append(False)
    elif not args.passwd:
        # Get password if not provided
        args.passwd = [getpass("Enter password, or continue with null-value: ")]
    try:
        launcher(args)
    except KeyboardInterrupt:
        print("\n[!] Key Event Detected, Closing...")
        exit(0)