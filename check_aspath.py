#!/usr/bin/env python
#
# $LastChangedBy: jbond $ 
# $LastChangedDate: 2013-02-19 18:22:27 +0100 (Tue, 19 Feb 2013) $
# $Id: check_aspath.py 16838 2013-02-19 17:22:27Z jbond $
# $HeadURL: svn+ssh://svn.ripe.net/var/svn/cfengine/ncc/configs/trunk/export/nagios_custom_checks/GII/check_aspath.py $
# $Rev: 16838 $

import json, urllib2, argparse, sys

parser = argparse.ArgumentParser(description='Nagios check. Uses RIPEstat Looking glass data call to check if there are any route hijacks')
parser.add_argument('--statserver', required=False, nargs=1,  help='RIPEstat server to use', default='stat.ripe.net')
parser.add_argument('--prefix', required=True, help='The prefix to search in slash notation')
parser.add_argument('--origin', required=True,  help='The correct origin ASN')
parser.add_argument('--transit', required=False,  help='comma seperated list of transit ASNs')
#default is 3 to exlude peers who pear with ris and also peer with the origin as
#for users with only transit peerings a value of 2 would make more sense
parser.add_argument('--minpath',  help='the minimum as hop count to consider', default=3, type=int)
parser.add_argument('-w', '--warn', help='Warning #peers with bad routes', default=1, type=int )
parser.add_argument('-c', '--crit', help='Criticle #peers with bad routes', default=5, type=int )
parser.add_argument('-v', help='Be more verbose', action='count')
args = parser.parse_args()

if args.transit:
    transit = args.transit.split(',')
origin = args.origin.split(',')
nagios_status = 0
origin_errors = 0
transit_errors = 0
nagios_message = ""
url = "https://%s/data/looking-glass/data.json?resource=%s" % (args.statserver, urllib2.quote(args.prefix, ''))
lookingglass_raw = urllib2.urlopen(url)
lookingglass_json = json.load(lookingglass_raw)
if lookingglass_json['data_call_status'] != "supported":
    print "WARN: %s is under maintance " % (args.statserver)
    sys.exit(1)
for rrc in lookingglass_json['data']['rrcs']:
    for peer in lookingglass_json['data']['rrcs'][rrc]['entries']:
        aspath = peer['as_path'].split()
        details = peer['details'][0].split()
        peer_addr = details[0]
        nexthop = details[2]
        router_id = details[3]
        
        if len(aspath) > args.minpath:
            if aspath[-1]  not in origin :
                origin_errors += 1
                nagios_message = nagios_message + ( "Origin missmatch %s (%s): %s; " % (rrc, peer_addr, aspath[-1]))
            if args.transit:
                if aspath[-2]  not in transit :
                    transit_errors += 1
                    nagios_message = nagios_message + ( "Transit missmatch %s (%s): %s; " % (rrc, peer_addr, aspath[-2]))

if origin_errors == 0 and transit_errors == 0:
    nagios_message = "OK: %s Origin is %s " % (args.prefix, args.origin)
    if args.transit:
        nagios_message = "%s and all transits match %s" % (nagios_message, args.transit) 
elif origin_errors >= args.crit or transit_errors >= args.crit:
    nagios_status = 2
    nagios_message = "ERROR: " + nagios_message
elif origin_errors >= args.warn or transit_errors >= args.warn:
    nagios_status = 1
    nagios_message = "WARN: " + nagios_message

print nagios_message
sys.exit(nagios_status)

# vim: set expandtab tabstop=4 shiftwidth=4 autoindent :
