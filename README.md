## LDAP_Search

![](https://img.shields.io/badge/Python-2.7,%203.6+-blue.svg)&nbsp;&nbsp;
![](https://img.shields.io/badge/License-GPL%203.0-green.svg)

LDAP_Search can be used to enumerate Users, Groups, Computers, Domain Policies, and Domain Trusts within a Windows environment. Authentication can be performed using traditional username and password, or NTLM hash. In addition, this tool has been modified to allow brute force/password-spraying via LDAP. 

Ldap_Search is compatible with Python 2.7 / 3.6+ and makes use of the [Impacket](https://github.com/SecureAuthCorp/impacket/) library to perform the main operations.

## Installation
```bash
git clone --recursive https://github.com/m8r0wn/ldap_search
cd ldap_search
sudo python3 setup.py install
```

## Usage
Password spray with LDAP:
```bash
ldap_search -U users.txt -P 'Summer2019!' -d demo.local
```

Enumerate all active users on a domain:
```bash
ldap_search users -u user1 -p Password1 -d demo.local
```

Lookup a single user and display attributes:
```bash
ldap_search users -q AdminUser -u user1 -p Password1 -d demo.local
```

Enumerate all computers on a domain and resolve IP addresses:
```bash
ldap_search computers -r -u user1 -p Password1 -d demo.local
```

Search for end of life systems on the domain:
```bash
ldap_search computers -q eol -u user1 -p Password1 -d demo.local -s DC01.demo.local
```

Query group members:
```bash
ldap_search groups -q "Domain Admins" -u user1 -p Password1 -d demo.local
```

Domain password policy:
```bash
ldap_search domain -u user1 -p Password1 -d demo.local
```

Write a custom query:
```bash
ldap_search custom -q '(objectClass=*)' -a 'objectName' -u user1 -p Password1 -d demo.local
```

## Query Types
```
User
  active / [None] - All active users (Default)
  all - All users, even disabled
  [specific account or email] - lookup user, ex. "m8r0wn"
  
group
  [None] - All domain groups
  [Specific group name] - lookup group members, ex. "Domain Admins"
 
computer
  [None] - All Domain Computers
  eol - look for all end of life systems on domain

Domain
    [None] - Domain's password policy

Trust
    [none] - Domain Trust information
```

## Options
```
  -q QUERY          Specify user or group to query
  -a ATTRS          Specify attrs to query
  -u USER           Single username
  -U USER           Users.txt file
  -p PASSWD         Single password
  -P PASSWD         Password.txt file
  -H HASH           Use Hash for Authentication
  -d DOMAIN         Domain (Ex. demo.local)
  -s SRV, -srv SRV  LDAP Server (optional)
  -r                Use DNS to resolve records
  -t TIMEOUT        Connection Timeout (Default: 4)
  -v                Show attribute fields and values
  -vv               Show connection attempts and errors
```
