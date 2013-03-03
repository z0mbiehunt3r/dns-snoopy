#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
DNS Cache Snooper - Check for DNS cache snooping vulnerability and snoop cache
Copyright (C) 2011  Alejandro Nolla Blanco - alejandro.nolla@gmail.com 
Nick: z0mbiehunt3r - @z0mbiehunt3r
Blog: navegandoentrecolisiones.blogspot.com


Thanks to:
Rubén Garrote García (Boken) for ideas and helping me
Daniel García García (Crohn) for ideas and helping me
Buguroo and Ecija team!


This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

'''
Sent from the skies jumped into the unknown
The march to Berlin has begun
Spearhead the charge surrounded by foes
Eagles are leading the way
                 Sabaton - Screaming Eagles
'''

import multiprocessing
import re
import sys
import time

try:
    import argparse
except :
    print "[-] You need argparse"
    sys.exit(0)

try:
    import dns.resolver
    import dns.flags
    import dns.set
except :
    print "[-] You need DNS-python (http://www.dnspython.org/)"
    sys.exit(0)


########################################################################
class cParams():
    """Class used to set some parameters"""

    #----------------------------------------------------------------------
    def __init__(self):
        """Constructor"""
        self.USE_COLOURS = False
        self.NORMAL_OUTPUT = None # writer for output, normally the screen
        self.ERROR_OUTPUT = None # writer for output, normally the screen
        self.args = []
    
    def set_use_colours(self, value):
        self.USE_COLOURS = value


    def set_normal_output(self, value):
        self.NORMAL_OUTPUT = value


    def set_error_output(self, value):
        self.ERROR_OUTPUT = value


#----------------------------------------------------------------------
def printMessage(message, kind, options):
    """
    Function used to print some message to file descriptor
    
    @param message: Message to show, format like "[+] Message" or "<-> Message"
    @type message: str
    
    @param kind: Kind of error - info/less/plus/error/verbose    
    @type kind: str
    """
    
    # Split "prompt" from message like "[!] Some weird error" or like "<-> Some info"
    srematch = re.search("(\s*[\[\<].{1}[\]|>])(.+)", message)
    if srematch is None:
        raise Exception, "Error spliting message to print"
    message_original = message
    prompt = srematch.group(1)
    message = srematch.group(2)
    
    if kind == "info":
        if options.USE_COLOURS: 
            options.NORMAL_OUTPUT.write(chr(27)+"[0;93m"+prompt+chr(27)+"[0m")
            options.NORMAL_OUTPUT.write(message+"\n")
        else:
            options.NORMAL_OUTPUT.write(message_original+"\n")
    elif kind == "less":
        if options.USE_COLOURS:
            options.NORMAL_OUTPUT.write(chr(27)+"[0;34m"+prompt+chr(27)+"[0m")
            options.NORMAL_OUTPUT.write(message+"\n")
        else:
            options.NORMAL_OUTPUT.write(message_original+"\n")
    elif kind == "plus":
        if options.USE_COLOURS:
            options.NORMAL_OUTPUT.write(chr(27)+"[0;32m"+prompt+chr(27)+"[0m")
            options.NORMAL_OUTPUT.write(message+"\n")
        else:
            options.NORMAL_OUTPUT.write(message_original+"\n")
    elif kind == "error":
        if options.USE_COLOURS:
            options.ERROR_OUTPUT.write(chr(27)+"[0;31m"+prompt+chr(27)+"[0m")
            options.ERROR_OUTPUT.write(message+"\n")
        else:
            options.NORMAL_OUTPUT.write(message_original+"\n")
    elif kind == "verbose":
        if options.USE_COLOURS:
            options.NORMAL_OUTPUT.write(chr(27)+"[0;35m"+prompt+chr(27)+"[0m")
            options.NORMAL_OUTPUT.write(message+"\n")
        else:
            options.NORMAL_OUTPUT.write(message+"\n") 
    

#----------------------------------------------------------------------
def checkDNSCacheAvailability(domain, progOptions):
    """
    Check if DNS server/s for given domain resolve cached queries
    
    @param domain: Domain trying to snoop
    @type domain: str
    
    @return: List with DNS which resolve cached queries, otherwise returns an empty list
    @rtype: list
    """
    
    vulnerable_dns_servers = []
    # Just because they are so common and probably will be already resolved
    common_domains = ["google.es","google.com","facebook.com","youtube.com","yahoo.com","live.com",
                      "baidu.com","wikipedia.org","blogger.com","msn.com","twitter.com","wordpress.com",
                      "amazon.com","adobe.com", "microsoft.com"]
    
    # Get NS list
    ns_servers = getNSList(domain, progOptions, showinfo=False)
    printMessage("[*] Checking cache responses availability", "info", progOptions)
    for ns in ns_servers:
        # Get DNS server IP
        ns_ip = resolveDNSRecord(ns, progOptions, 'A')
        # Check common domains
        for dom in common_domains:
            if dnsCacheRequest(dom, ns_ip):
                printMessage("   [+] %s resolve cached queries" %ns, "plus", progOptions) 
                vulnerable_dns_servers.append(ns)
                break
    
    if len(vulnerable_dns_servers) == 0:
        printMessage("[-] DNS servers for %s domain not vulnerable to DNS cache snooping attack" %domain, "less", progOptions)
        sys.exit(1)

    return vulnerable_dns_servers


#----------------------------------------------------------------------
def getNSList(domain, progOptions, showinfo):
    """
    Retrieves list with NS records for given domain
    
    @param domain: Domain to query for NS records
    @type domain: str
    
    @return: List with NS records
    @rtype: list
    """

    if showinfo:
        printMessage("[*] Obtaining DNS servers", "info", progOptions)
    ns_servers = []
    answers = dns.resolver.query(domain, 'NS')
    for x in answers:
        x = str(x).strip(".")
        if showinfo:
            printMessage("   [+] DNS server: %s" % x, "plus", progOptions)
        # Remove last dot (ns1.domain.com.)
        ns_servers.append(str(x))

    return ns_servers


#----------------------------------------------------------------------
def resolveDNSRecord(nameserver, progOptions, record):
    """
    Resolve DNS record
    
    @param nameserver: DNS server to query at
    @type nameserver: str

    @param record: DNS tpye record (Ex. PTR)
    @type record: str

    @return: First IP address of DNS given record
    @rtype: str
    """
    
    answers = dns.resolver.query(nameserver, record)
    # answers.rrset looks like ns1.domain.es. 16308 IN A XXX.XXX.XXX.XXX
    # answers.rrset[0] is an IP (<class 'dns.rdtypes.IN.A.A'>)
    # do cast to str and return an string containing an IP
    ip_address = str(answers.rrset[0])
    
    return ip_address    


#----------------------------------------------------------------------
def dnsCacheRequest(domain, nameserver_ip, checkttl=False, dns_snooped=False):
    """
    Make DNS cached query (Recursion Desired bit = 0) for given domain against nameserver_ip
    
    @param domain: Domain to check if it's cached
    @type domain: str
    
    @param namserver_ip: IP address of DNS server to be queried
    @type nameserver_ip: str

    @param checkttl: Check TTL or not
    @type checkttl: bool

    @param dns_snooped: DNS server name being snooped
    @type dns_snooped: str

    @return: Boolean showing if domain is cached or not
    """
    
    resolver = dns.resolver
    query = dns.message.make_query(domain, dns.rdatatype.A, dns.rdataclass.IN)
    # Negate recursion desired bit
    query.flags ^= dns.flags.RD
    
    # GET NS IP
    dns_response = dns.query.udp(q=query,where=nameserver_ip)
    '''
    Check length major of 0 to avoid those answers with root servers in authority section (reflected DNS DDoS }:D )
    ;; QUESTION SECTION:
    ;www.facebook.com.        IN    A
    
    ;; AUTHORITY SECTION:
    com.            123348    IN    NS    d.gtld-servers.net.
    com.            123348    IN    NS    m.gtld-servers.net.
    [...]
    com.            123348    IN    NS    a.gtld-servers.net.
    com.            123348    IN    NS    g.gtld-servers.net.    
    '''
    if len(dns_response.answer) > 0 and checkttl:
        # Get cached TTL
        ttl_cached = dns_response.answer[0].ttl
        if progOptions.verbosity:
            printMessage("      <-> %s cached TTL: %s" %(domain ,ttl_cached), "verbose", progOptions)
        # First, get NS for cached domain (just first)
        cached_domain_dns = getNSList(domain, progOptions, showinfo=False)[0]
        # After, resolve its IP address
        cached_domain_dns_IP = resolveDNSRecord(cached_domain_dns, progOptions, 'A')
        # Now, obtain original TTL
        query = dns.message.make_query(domain, dns.rdatatype.A, dns.rdataclass.IN)
        query.flags ^= dns.flags.RD
        # GET NS IP
        dns_response = dns.query.udp(q=query,where=cached_domain_dns_IP)
        ttl_original = dns_response.answer[0].ttl
        if progOptions.verbosity:
            printMessage("      <-> %s original TTL: %s" %(domain, ttl_original), "verbose", progOptions)
        cached_ago = ttl_original-ttl_cached
        printMessage("   [+] %s was cached about %s ago aprox. [%s]" %
                     (domain, time.strftime('%H:%M:%S', time.gmtime(cached_ago)), dns_snooped), "plus", progOptions)
    
    elif len(dns_response.answer) > 0:
        return 1    
    
    return 0


#----------------------------------------------------------------------
def worker(domains, nameserver_ip, vulnerable_ns):
    """
    Worker to process queues
    
    @param domains: List with domains to query
    @type domains: multiprocessing queue
    
    @param vulnerable_ns: DNS server being snooped
    @type vulnerable_ns: str
    """

    try:
        while len(domains) > 0:
            domain = domains.pop()
            # Check for cached domain
            dnsCacheRequest(domain, nameserver_ip, checkttl=True, dns_snooped=vulnerable_ns)
    
    except KeyboardInterrupt:
        printMessage("[!] Ctrl^C - killing process...", "error", progOptions)
        return

    except Exception, e:
        printMessage("[-] %s" %str(e), "errror", progOptions)
        return


#----------------------------------------------------------------------
def readDomainsToSnoop(file):
    """
    Reads file and return content as list
    
    @param file: File containing domains to check if cached
    @type file: str

    @return: List with domains (lines!) in text file
    @rtype: list
    """
    
    fd = open(file, "r")
    domains = fd.readlines()
    # Remove line feed
    domains = map(str.rstrip, domains)
    fd.close()
    return domains
    

#----------------------------------------------------------------------
def banner():
    banner = '''
        |----------------------------------------------------------|
        |                      DNS Cache Snooper                   |
        |               Alejandro Nolla (z0mbiehunt3r)             |
        |----------------------------------------------------------|\n'''
    print banner    


#----------------------------------------------------------------------
def checkArgs():
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit()



if __name__=='__main__':
    banner()
    
    parser = argparse.ArgumentParser()
    gr1 = parser.add_argument_group("Main options")
    gr1.add_argument('-d', '--domain', dest='domain', required=False, help='domain to snoop')
    gr1.add_argument('-f', '--file', dest='file', required=False, default="domains.txt", help='list of domain to check if it\'s cached (default=domains.txt)')
    gr1.add_argument('-p', '--processes', dest='processes', action='store', type=int, help='number of process to use (default one per core)', default=multiprocessing.cpu_count())
    
    gr2 = parser.add_argument_group("Disply options")
    gr2.add_argument('-v', '--verbose', dest='verbose', default=False,  action='store_true', help='show extra info')
    gr2.add_argument('-c', '--colours', dest='colour', default=False,  action='store_true', help='coloured output')
    
    
    args = parser.parse_args()
    
    checkArgs()
    
    progOptions = cParams()
    progOptions.set_normal_output(sys.stdout)
    progOptions.set_error_output(sys.stderr)
    progOptions.set_use_colours(args.colour)
    progOptions.domain = args.domain
    progOptions.file = args.file
    progOptions.verbosity = args.verbose
    progOptions.processes = args.processes

    try:
        vulnerable_dns = checkDNSCacheAvailability(progOptions.domain, progOptions)
        if progOptions.verbosity:
            printMessage("[v] Reading domains list to snoop", "verbose", progOptions)
        domains = readDomainsToSnoop(progOptions.file)
        printMessage("[*] Going to snoop domains with %s" %vulnerable_dns, "info", progOptions)
        for vulnerable_ns in vulnerable_dns:
            nameserver_ip = resolveDNSRecord(vulnerable_ns, progOptions, 'A')
            
            # Mutable list to store domains to check
            m_domains_input = multiprocessing.Manager().list()
            m_domains_input.extend(domains)
            
            # Pool of processes
            m_pool = multiprocessing.Pool(progOptions.processes)
           
            # Create processes and start working!
            for p in range(progOptions.processes):
                m_pool.apply_async(worker, (m_domains_input, nameserver_ip, vulnerable_ns))
           
            # Wait until all domains have been processed
            m_pool.close()
            m_pool.join()            
                    
        printMessage("[*] Finished!", "info", progOptions)    
    
    except KeyboardInterrupt:
        printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit(0)

    except Exception, e:
        printMessage("[-] %s" %str(e), "errror", progOptions)
        sys.exit(0)
        
        
        
        
