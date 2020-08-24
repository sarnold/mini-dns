#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Target:   Python 3.6
#
# Copyright (c) 2020 by Fred Morris Tacoma WA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""TCP-only DNS Forwarder.

Please read the README. Daemon usage:

    forwarder.py start <udp-listen-address> <dns-server-address> [<listen_port>]
    forwarder.py stop|status

The above will run the script in the background. dns-server-address
should be one of your configured local caching resolvers or a "trusted"
provider of DNS over TLS.

After running the script edit your network settings and change your
resolver to udp-listen-address and the default port 5353.  Use the
optional last arg above to set a different listen port (eg, you can
use port 53 with the proper permissions).

udp-listen-address will typically be 127.0.0.1 for IP4 or ::1 for IP6.

The Daemon version always establishes the connection with TLS, contacting
the server on port 853. (Also known as "DoT".)
"""
import os
import sys
import asyncio
import ssl
import logging
import logging.handlers

from daemon import Daemon


if os.getuid() == 0:
    pid_file = os.path.join('/run', 'forwarder.pid')
else:
    import tempfile
    pid_file = os.path.join(tempfile.gettempdir(), 'forwarder.pid')

logger = logging.getLogger(__name__)

# set log level and handler/formatter
logger.setLevel(logging.DEBUG)
logging.getLogger('node_tools.helper_funcs').level = logging.DEBUG

handler = logging.handlers.SysLogHandler(address='/dev/log', facility='daemon')
formatter = logging.Formatter('%(module)s: %(funcName)s+%(lineno)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

stdout = '/tmp/forwarder.log'
stderr = '/tmp/forwarder_err.log'


class UDPListener(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        return

    async def handle_request(self, request, addr):
        reader, writer = await asyncio.open_connection(self.remote_address, self.ssl and 853 or 53, ssl=self.ssl)
        # NOTE: When using TCP the request and response are prepended with
        # the length of the request/response.
        writer.write(len(request).to_bytes(2, byteorder='big')+request)
        await writer.drain()
        response_length = await reader.read(2)
        response = await reader.read(int.from_bytes(response_length, byteorder='big'))
        writer.close()
        self.transport.sendto(response, addr)
        return

    def datagram_received(self, request, addr):
        self.event_loop.create_task(self.handle_request(request, addr))
        return


class dnsDaemon(Daemon):
    def cleanup(self):
        transport.close()
        event_loop.close()

    def run(self):
        event_loop.run_forever()


if __name__ == "__main__":

    listen_port = 5353
    if len(sys.argv) == 5:
        listen_port = sys.argv[4]
    if 'start' == sys.argv[1]:
        print('Using listen port: {}'.format(listen_port))

    if len(sys.argv) >= 4 and 'start' == sys.argv[1]:
        try:
            listen_address, remote_address = sys.argv[2:4]
        except Exception as exc:
            logger.warning('Argument error is {}'.format(exc))

        event_loop = asyncio.get_event_loop()
        listener = event_loop.create_datagram_endpoint(UDPListener, local_addr=(listen_address, listen_port))

        try:
            transport, service = event_loop.run_until_complete(listener)
        except PermissionError as exc:
            logger.error('error opening listen port {}'.format(listen_port))
            logger.error('exception was {}'.format(exc))
            print('Port error: {}'.format(exc))
            sys.exit(1)

        service.remote_address = remote_address
        service.event_loop = event_loop
        service.ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    daemon = dnsDaemon(pid_file, verbose=1, use_cleanup=True)
    if sys.argv[1] not in ('start', 'stop', 'status'):
        print("Unknown command")
        sys.exit(2)
    if len(sys.argv) == 4 or len(sys.argv) == 5:
        if 'start' == sys.argv[1]:
            logger.info('Starting')
            daemon.start()
        sys.exit(0)
    elif len(sys.argv) == 2:
        if 'stop' == sys.argv[1]:
            logger.info('Stopping')
            daemon.stop()
        elif 'status' == sys.argv[1]:
            res = daemon.status()
            logger.info('Status is {}'.format(res))
        sys.exit(0)
    else:
        print("Usage: {} start <udp-listen-address> <remote-server-address>".format(sys.argv[0]))
        print("       {} stop|status".format(sys.argv[0]))
        sys.exit(2)
