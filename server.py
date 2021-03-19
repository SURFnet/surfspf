from __future__ import print_function

from dnslib import RR,QTYPE,RCODE,A,AAAA,parse_time
from dnslib.label import DNSLabel
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

class ShellResolver(BaseResolver):

    def __init__(self,routes,origin,ttl):
        self.origin = DNSLabel(origin)
        self.ttl = parse_time(ttl)

    def check_ip(self, ip_address):
        try:
            if len(ip_address.split('.')) == 4:
                ip = netaddr.IPAddress(ip_address)
                return ip.version, ip.format()
            elif len(ip_address.split('.')) == 32:
                ip = netaddr.IPAddress(':'.join([ip_address.replace('.','')[i:i+4] for i in range(0, 32, 4)]))
                return ip.version, ip.format()
        except:
            print('not valid ip_address found')
        return -1, False


    def spfcheck(self, qname):
        data = dict((key, value) for (value, key) in re.findall('([a-zA-Z0-9\-\.]+).\_(\w+).',str(qname)))
        # print(data)
        # print('SPF check on allowed (resolved) IP {} in _surfspf.{}'.format(data['ip'], data['domain']))
        # print(netaddr.IPNetwork(data['ip']))
        if 'ip' in data:
            ip_version, ip_address = self.check_ip(data['ip'])
            if ip_address!= False:
                spf_result, spf_reason = spf.check2(i=ip_address,
                                        s='surfspfcheck@{}'.format(data['domain']),
                                        h=data['helo'], verbose=False)
                print(spf_result, spf_reason)
                # spf_result = 'pass'
                if spf_result == 'pass':
                    return ip_version, ip_address
                else:
                    return False, False
            else:
                return -1, False
        else:
            return -1, False

    def resolve(self,request,handler):
        reply = request.reply()
        qtype = QTYPE[request.q.qtype]
        qname = request.q.qname
        # with 'exists:%{i}._ip.%{h}._domain.surfspf.net' in SPF-record of 'surf.nl'
        # mail from: 'tim.deboer@surf.nl' via 'outgoing2-ams.mf.surf.net' should result in a A-record query;
        # '145.0.1.5._ip.outgoing2-ams.mf.surf.net._helo.surf.nl._domain.surfspf.net.'
        if str(self.origin) in str(qname):
            if qtype == 'A':
                ip_version, ip_address = self.spfcheck(qname)
                if ip_version == -1:
                    reply.header.rcode = RCODE.SERVFAIL
                elif ip_version == 4:
                    reply.add_answer(RR(qname,QTYPE.A,ttl=self.ttl,
                                        rdata=A(ip_address)))
                elif ip_version == 6:
                    reply.add_answer(RR(qname,QTYPE.AAAA,ttl=self.ttl,
                                        rdata=AAAA(ip_address)))
                else:
                    reply.header.rcode = RCODE.NXDOMAIN
            else:
                reply.header.rcode = RCODE.NXDOMAIN
        else:
            reply.header.rcode = RCODE.REFUSED
        return reply

if __name__ == '__main__':

    import argparse,time,re,spf,netaddr

    p = argparse.ArgumentParser(description="Shell DNS Resolver")
    p.add_argument("--origin","-o",default=".",
                    metavar="<origin>",
                    help="Origin domain label (default: .)")
    p.add_argument("--ttl","-t",default="60s",
                    metavar="<ttl>",
                    help="Response TTL (default: 60s)")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Server port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Listen address (default:all)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    resolver = ShellResolver({},args.origin,args.ttl)
    logger = DNSLogger(args.log,args.log_prefix)

    print("Starting SPF Resolver (%s:%d) [UDP]" % (
                        args.address or "*",
                        args.port))

    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger)
    udp_server.start_thread()


    while udp_server.isAlive():
        time.sleep(1)
