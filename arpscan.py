#!/usr/bin/env python
# -*- encoding: utf-8 -*-

# Copyright (c) 2017, Frédéric Fauberteau
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import argparse
import re
import shutil
import subprocess
import sys

class ArpScanner:
    interface = ''
    hosts = ''

    def __init__(self, interface, hosts='--localnet'):
        self.interface = interface
        self.hosts = hosts

    def scan(self):
        sudo = shutil.which('sudo')
        if not sudo:
            raise FileNotFoundError('sudo binary is needed')
        arpscan = shutil.which('arp-scan')
        if not arpscan:
            raise FileNotFoundError('arp-scan binary is needed')
        if not subprocess.getstatusoutput(sudo + ' -n echo 0')[0] == 0:
            raise PermissionError('You must be a sudoers without password')
        pargs = [sudo, '-n', arpscan, '-I', self.interface, self.hosts]
        try:
            out = subprocess.check_output(pargs, universal_newlines=True, timeout=5)
        except subprocess.TimeoutExpired:
            pass
        re_ip = r'(?P<ip>((2[0-5]|1[0-9]|[0-9])?[0-9]\.){3}((2[0-5]|1[0-9]|[0-9])?[0-9]))'
        re_mac = r'(?P<mac>([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2}))'
        pattern = re.compile(re_ip + '\s+' + re_mac)
        return [match.groupdict() for match in re.finditer(pattern, out)]

def main():
    desc = 'Command-line tool for network discovery. \
            It is a Python wrapper for arp-scan tool. \
            Both this command and sudo are needed.'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('interface', help='interface to scan')
    parser.add_argument('-H', '--hosts', default='--localnet', help='host or network to scan')
    args = parser.parse_args()
    arpscan = ArpScanner(args.interface, args.hosts)
    for entry in arpscan.scan():
        print('{mac}: {ip}'.format(**entry))

if __name__ == '__main__':
    sys.exit(main())
