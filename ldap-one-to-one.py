#!/usr/bin/python2

#This program selects a single source object, from which the attribues sAttributes are copied over to the found destination objects
#When replace option is False then existing destination attributes are not updated

from optparse import OptionParser
import sys
import ldap
import ldap.modlist as modlist  
import six
import re

#LDAP connection wrapper
def connectLdap(url, binddn, password):
    try:    
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        l = ldap.initialize(url)
        l.set_option(ldap.OPT_REFERRALS ,0)
        l.set_option(ldap.OPT_REFERRALS, 0)
        l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        l.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
        l.set_option(ldap.OPT_X_TLS_DEMAND, True)
        l.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        l.simple_bind_s(binddn, password)
        return l
    except ldap.LDAPError as e:
        print("LDAP error: %s -- executution halted" % e)
        sys.exit(2)

#Do searches until we run out of "pages" to get from the LDAP server.
#We will return a hash that has the dn as a key and second has for attributes (key) and their value
def pagedSearch(connect, basedn, filter, attribs):

    page_control = ldap.controls.libldap.SimplePagedResultsControl(False, size=1000, cookie='')

    response = connect.search_ext(basedn, ldap.SCOPE_SUBTREE, filter, attribs, serverctrls=[page_control])

    result = {}

    while True:
        rtype, rdata, rmsgid, serverctrls = connect.result3(response)
    
        for r in rdata:
          result[r[0]] = r[1]

        controls = [c for c in serverctrls if c.controlType == ldap.controls.libldap.SimplePagedResultsControl.controlType]

        if not controls:
            print('The server ignores RFC 2696 control')
            break

        if not controls[0].cookie:
            break

        page_control.cookie = controls[0].cookie
        response = connect.search_ext(basedn, ldap.SCOPE_SUBTREE, filter, attribs, serverctrls=[page_control])
    return result

#Parse the options
def options(parser):
    parser.add_option("--sLdap", dest="source", help="LDAP url of source")
    parser.add_option("--sBind", dest="sourceBind", help="source bind")
    parser.add_option("--sPass", dest="sourcePass", help="source password")
    parser.add_option("--sBaseDN", dest="sBaseDN", help="source password")
    parser.add_option("--sAttribs", dest="sAttribs", help="comma seperated attributes to copy") 
    parser.add_option("--sFilter", dest="sFilter", help="source filter which objects to select")

    parser.add_option("--dLdap", dest="dest", help="LDAP url of destination")
    parser.add_option("--dBind", dest="destBind", help="dest bind")
    parser.add_option("--dPass", dest="destPass", help="dest password")
    parser.add_option("--dBaseDN", dest="dBaseDN", help="source password")
    parser.add_option("--dFilter", dest="dFilter", help="destination filter that should contain [sIdentifiers] tag to uniquely find matching object in destination directory. F.i: (&(objectClass=user)[sIdentifiers]) Where [sIdentifiers] will be replaced with evaluated --sIdentifiers")
    parser.add_option("--dAttribs", dest="dAttribs", help="comma seperated attributes to be copied (matching 1 to 1 with sAttrib)") 
    parser.add_option("--sIdentifiers", dest="sIdentifiers", help=" LDAP search string template to uniquely identify a user in destination directory; f.i. (uid=[uid])(groupNumber=[gidNumber] where [uid] and [gidNumber] are replace with the source's attribute values is changed with source value")

    parser.add_option("-r", "--replace", action="store_true", dest="replace", help="replace destination attributes when they differ between source and dest, default is false", default=False) 
    parser.add_option("-t", "--simulate", action="store_true", dest="simMode", help="Only print output the unencoded LDIF output, for inspection and will not update the directory", default=False) 

#Split a comma seperated string into an array and strip leading and trailing spaces
def splitComma(data):
    return [x.strip() for x in data.split(',')]

def fillIn(idFilter, sAttribs):
    m = re.search("\[\w+\]", idFilter)
    while m is not None:
        f = re.search("\[(\w+)\]", idFilter) 
        idFilter = idFilter.replace("["+f.group(1)+"]", sAttribs[f.group(1)][0])
        m = re.search("\[\w+\]", idFilter)
    return idFilter

def getAllAttribs(sIdentifiers, sAttribs):
    result = splitComma(sAttribs)
    idAttribs = re.findall("\[(\w+)\]", sIdentifiers)
    result = result + idAttribs 
    return result

if __name__ == "__main__":
    parser = OptionParser()
    options(parser)
    if len(sys.argv[1:]) == 0:
        print "no argument given!"
        parser.print_help()
        sys.exit(2)
    options, remainder = parser.parse_args()

    #Exceptuions are handled in the connectLdap for briefness, when something goes wrong it will exit the program
    source = connectLdap(options.source, options.sourceBind, options.sourcePass)
    dest = connectLdap(options.dest, options.destBind, options.destPass)

    try:
        srcData = pagedSearch(source, options.sBaseDN, options.sFilter, getAllAttribs(options.sIdentifiers, options.sAttribs))
    except:
        print(sys.exc_info()[0])
        sys.exit(2)

    #These will never change so no need to be in the loop
    ldAttribs = splitComma(options.dAttribs)
    lsAttribs = splitComma(options.sAttribs)

    #loop through the dst objects and update if required
    for sdn in srcData:
        ldif = ""    
        #we iterate through the attributes as an indexed array so that we can match the source and destination attributes by index, this allows us to
        #copy the source attribute value to a different destination attribute
        #Which means that options.sAttribs[0] will be copied to options.dAttribs[0], options.sAttribs[1] will be copied to options.dAttribs[1]... etc
        i = 0
        sAttribs = srcData[sdn]

        Identifier = fillIn(options.sIdentifiers, sAttribs)
        dFilter = options.dFilter.replace("[sIdentifiers]", Identifier)    
        dstData = pagedSearch(dest, options.dBaseDN, dFilter, splitComma(options.dAttribs))

        if len(dstData) > 1:
            print("--sIdentifiers not unique enough to find 1 destination object!")
            sys.exit(2) 
        
        #iterate over the single object so we have ease access to dn
        for ddn in dstData:
            dAttribs = dstData[ddn]
            i = 0
            for dAttrib in ldAttribs:
                if lsAttribs[i] in sAttribs and dAttrib not in dstData[ddn]:
                    ldif += "add: %s\n%s: %s\n-\n" % (ldAttribs[i], ldAttribs[i], sAttribs[lsAttribs[i]][0])
                    if not options.simMode:
                        dest.modify_s(ddn, [(ldap.MOD_ADD, ldAttribs[i], sAttribs[lsAttribs[i]][0])] )
                
                elif lsAttribs[i] in sAttribs and sAttribs[lsAttribs[i]][0] != dAttribs[ldAttribs[i]][0] and options.replace:
                    ldif += "replace: %s\n%s: %s\n-\n" % (ldAttribs[i], ldAttribs[i], sAttribs[lsAttribs[i]][0])
                    if not options.simMode:
                       dest.modify_s(ddn, [(ldap.MOD_REPLACE, ldAttribs[i], sAttribs[lsAttribs[i]][0])])
                i += 1

        if len(ldif) > 0:
             print("dn: %s\nchangetype: modify\n%s" % (ddn, ldif))
