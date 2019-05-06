QUERIES = { 'users_active'        : '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
          'users_all'           : '(&(objectCategory=person)(objectClass=user))',
          'users_email_search'  : '(&(objectClass=user)(mail:={}))',
          'users_account_search': '(&(objectClass=user)(sAMAccountName:={}))',
          'cpu_all'             : '(&(objectClass=Computer))',
          'groups_all'          : '(&(objectCategory=group))',
          'group_members'      : '(&(objectCategory=group)(cn={}))',
          'domain_policy'       : '(objectClass=domain)',
          'domain_trust'        : '(objectClass=trustedDomain)'
          }

ATTRIBUTES = { 'users' : [ 'Name', 'userPrincipalName', 'sAMAccountName', 'mail', 'company', 'department', 'mobile',
                           'telephoneNumber', 'badPwdCount', 'userWorkstations', 'manager', 'memberOf', 'manager',
                           'whenCreated', 'whenChanged'],

            'cpu'   : ['dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack'],

            'groups': ['distinguishedName', 'cn', 'name', 'sAMAccountName', 'sAMAccountType', 'whenCreated', 'whenChanged'],

            'domain': [ 'cn', 'dc', 'distinguishedName', 'lockOutObservationWindow', 'lockoutDuration',
                      'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength', 'pwdProperties',
                      'pwdHistoryLength', 'nextRid', 'dn'],

            'trust' : ['cn', 'flatName', 'name', 'objectClass', 'trustAttributes', 'trustDirection', 'trustPartner',
                     'trustType'],
            }