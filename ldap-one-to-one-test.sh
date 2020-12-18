#!/usr/bin/bash
./ldap-bulkcopy.py  --sLdap="ldap://127.0.0.1/" \
		--sBind="cn=admin,dc=phonax" \
		--sPass="Phonax01" \
        --sBaseDN="ou=source,ou=users,dc=phonax" \
		--sAttribs="userPassword, description" \
        --sIdentifiers="(uid=[uid])(gidNumber=[gidNumber])" \
		--sFilter="(&(objectClass=posixAccount)(cn=*))" \
		--dLdap=ldap://127.0.0.1 \
		--dBind="cn=admin,dc=phonax" \
		--dPass="Phonax01" \
        --dBaseDN="ou=dest,ou=users,dc=phonax" \
		--dAttribs="userPassword, description" \
		--dFilter="(&(objectClass=posixAccount)[sIdentifiers])" \
        --simulate \
        --replace \
