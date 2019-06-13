#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
# Copyright 2016 Howard Liu
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import time
import socket
import errno
import struct
import logging
import traceback
import random
import cryptor
import eventloop
import shell
import common
from common import parse_header
if sys.platform == 'win32':
    # win_inet_pton injects inet_pton method into socket lib for
    # Windows Py < 3.4
    import win_inet_pton

# we clear at most TIMEOUTS_CLEAN_SIZE timeouts each time
TIMEOUTS_CLEAN_SIZE = 512

MSG_FASTOPEN = 0x20000000

# SOCKS METHOD definition
METHOD_NOAUTH = 0

# SOCKS command definition
CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

# for each opening port, we have a TCP Relay

# for each connection, we have a TCP Relay Handler to handle the connection

# for each handler, we have 2 sockets:
#    local:   connected to the client
#    remote:  connected to remote server

# for each handler, it could be at one of several stages:

# as sslocal:
# stage 0 auth METHOD received from local, reply with selection message
# stage 1 addr received from local, query DNS for remote
# stage 2 UDP assoc
# stage 3 DNS resolved, connect to remote
# stage 4 still connecting, more data from local received
# stage 5 remote connected, piping local and remote

# as ssserver:
# stage 0 just jump to stage 1
# stage 1 addr received from local, query DNS for remote
# stage 3 DNS resolved, connect to remote
# stage 4 still connecting, more data from local received
# stage 5 remote connected, piping local and remote

STAGE_INIT = 0
STAGE_ADDR = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_STREAM = 5
STAGE_DESTROYED = -1

# for each handler, we have 2 stream directions:
#    upstream:    from client to server direction
#                 read local and write to remote
#    downstream:  from server to client direction
#                 read remote and write to local

STREAM_UP = 0
STREAM_DOWN = 1

# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024
UP_STREAM_BUF_SIZE = 16 * 1024
DOWN_STREAM_BUF_SIZE = 32 * 1024

# helper exceptions for TCPRelayHandler


class BadSocksHeader(Exception):
    pass


class NoAcceptableMethods(Exception):
    pass

# helper exceptions for TCPRelayHandler


class BadSocksHeader(Exception):
    pass


class NoAcceptableMethods(Exception):
    pass


class TCPLogging(object):

    def __getattribute__(self, item):
        def f(*argv):
            pass
        import config
        if config.LOG_TCP:
            return getattr(logging, item, f)
        else:
            return f


class TCPRelayHandler(object):

    def __init__(self, server, fd_to_handlers, loop, local_sock, config,
                 dns_resolver, is_local):
        self._logging = TCPLogging()
        self._server = server
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_sock = local_sock
        self._remote_sock = None
        self._config = config
        if 'relay_info' not in self._config:
            self._config['relay_info'] = None
        self._dns_resolver = dns_resolver
        self.tunnel_remote = config.get('tunnel_remote', "8.8.8.8")
        self.tunnel_remote_port = config.get('tunnel_remote_port', 53)
        self.tunnel_port = config.get('tunnel_port', 53)
        self._is_tunnel = server._is_tunnel

        # TCP Relay works as either sslocal or ssserver
        # if is_local, this is sslocal
        self._is_local = is_local
        self._stage = STAGE_INIT
        self._cryptor = cryptor.Cryptor(config['password'],
                                        config['method'],
                                        config['crypto_path'])
        self._fastopen_connected = False
        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []
        self._upstream_status = WAIT_STATUS_READING
        self._downstream_status = WAIT_STATUS_INIT
        self._remote_address = None
        self._forbidden_iplist = config.get('forbidden_ip')
        if is_local:
            self._chosen_server = self._get_a_server()
        fd_to_handlers[local_sock.fileno()] = self
        local_sock.setblocking(False)
        local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        loop.add(local_sock, eventloop.POLL_IN |
                 eventloop.POLL_ERR, self._server)
        self.last_activity = 0
        self._update_activity()

    def __hash__(self):
        # default __hash__ is id / 16
        # we want to eliminate collisions
        return id(self)

    @property
    def remote_address(self):
        return self._remote_address

    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']
        if isinstance(server_port, list):
            server_port = random.choice(server_port)
        if isinstance(server, list):
            server = random.choice(server)
        self._logging.debug('chosen server: %s:%d', server, server_port)
        return server, server_port

    def _update_activity(self, data_len=0):
        # tell the TCP Relay we have activities recently
        # else it will think we are inactive and timed out
        self._server.update_activity(self, data_len)

    def _update_stream(self, stream, status):
        # update a stream to a new waiting status

        # check if status is changed
        # only update if dirty
        dirty = False
        if stream == STREAM_DOWN:
            if self._downstream_status != status:
                self._downstream_status = status
                dirty = True
        elif stream == STREAM_UP:
            if self._upstream_status != status:
                self._upstream_status = status
                dirty = True
        if not dirty:
            return

        if self._local_sock:
            event = eventloop.POLL_ERR
            if self._downstream_status & WAIT_STATUS_WRITING:
                event |= eventloop.POLL_OUT
            if self._upstream_status & WAIT_STATUS_READING:
                event |= eventloop.POLL_IN
            self._loop.modify(self._local_sock, event)
        if self._remote_sock:
            event = eventloop.POLL_ERR
            if self._downstream_status & WAIT_STATUS_READING:
                event |= eventloop.POLL_IN
            if self._upstream_status & WAIT_STATUS_WRITING:
                event |= eventloop.POLL_OUT
            self._loop.modify(self._remote_sock, event)

    def _write_to_sock(self, data, sock):
        # write data to sock
        # if only some of the data are written, put remaining in the buffer
        # and update the stream to wait for writing
        if not data or not sock:
            return False
        uncomplete = False
        try:
            l = len(data)
            s = sock.send(data)
            if s < l:
                data = data[s:]
                uncomplete = True
        except (socket.error, OSError, IOError) as e:
            error_no = eventloop.errno_from_exception(e)
            if sys.platform == "win32":
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK, errno.WSAEWOULDBLOCK):
                    uncomplete = True
            elif error_no in (errno.EAGAIN, errno.EINPROGRESS,
                              errno.EWOULDBLOCK):
                uncomplete = True
            else:
                shell.print_exception(e)
                self.destroy()
                return False
        if uncomplete:
            if sock == self._local_sock:
                self._data_to_write_to_local.append(data)
                self._update_stream(STREAM_DOWN, WAIT_STATUS_WRITING)
            elif sock == self._remote_sock:
                self._data_to_write_to_remote.append(data)
                self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            else:
                self._logging.error('write_all_to_sock:unknown socket')
        else:
            if sock == self._local_sock:
                self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
            elif sock == self._remote_sock:
                self._update_stream(STREAM_UP, WAIT_STATUS_READING)
            else:
                self._logging.error('write_all_to_sock:unknown socket')
        return True

    def _handle_stage_connecting(self, data, original_data):
        if self._config['relay_info']:
            # If in relay mode, send encrypted data (i.e. original data)
            self._data_to_write_to_remote.append(original_data)
            return
        elif not self._is_local:
            self._data_to_write_to_remote.append(data)
            return
        data = self._cryptor.encrypt(data)
        self._data_to_write_to_remote.append(data)

        if self._config['fast_open'] and not self._fastopen_connected:
            # for sslocal and fastopen, we basically wait for data and use
            # sendto to connect
            try:
                # only connect once
                self._fastopen_connected = True
                remote_sock = \
                    self._create_remote_socket(self._chosen_server[0],
                                               self._chosen_server[1])
                self._loop.add(remote_sock, eventloop.POLL_ERR, self._server)
                data = b''.join(self._data_to_write_to_remote)
                l = len(data)
                s = remote_sock.sendto(data, MSG_FASTOPEN,
                                       self._chosen_server)
                if s < l:
                    data = data[s:]
                    self._data_to_write_to_remote = [data]
                else:
                    self._data_to_write_to_remote = []
                self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
            except (socket.error, OSError, IOError) as e:
                if eventloop.errno_from_exception(e) == errno.EINPROGRESS:
                    # in this case data is not sent at all
                    self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                elif eventloop.errno_from_exception(e) == errno.ENOTCONN:
                    self._fastopen_connected = False
                    self._logging.error('fast open not supported on this OS')
                    self._config['fast_open'] = False
                    self.destroy()
                else:
                    shell.print_exception(e)
                    self.destroy()

    @shell.exception_handle(self_=True, destroy=True, conn_err=True)
    def _handle_stage_addr(self, data, original_data):
        # Socks ver. 5 connection request from client:
        # +--------------+-----+-----+-----+------+----------+----------+
        # | name         | VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
        # +--------------+-----+-----+-----+------+----------+----------+
        # | no. of bytes | 1   | 1   | 1   | 1    | VARIABLE | 2        |
        # +--------------+-----+-----+-----+------+----------+----------+
        #
        # VER: Always 0x05 for socks 5
        # CMD: 0x01-TCP stream, 0x02-TCP port binding, 0x03-UDP associate
        # RSV: Always 0x00
        # ATYP: 'Type of destination address'
        #       0x01-IPv4, 0x03-domain name, 0x04-IPv6
        # DST.ADDR: 4 bytes for IPv4 address
        #           1 byte of name length followed by 1–255 bytes the domain name
        #           16 bytes for IPv6 address
        # DST.PORT: 'Destination port number', unsigned big-endian integer
        #
        try:
            addr, port = self._local_sock.getpeername()[:2]
            if self._is_local:
                cmd = common.ord(data[1])
                if cmd == CMD_UDP_ASSOCIATE:
                    self._logging.debug('U[%d] UDP associate' %
                                        self._config['server_port'])
                    if self._local_sock.family == socket.AF_INET6:
                        # Second byte is status, 0x00 for means 'request granted'
                        # Third byte is RSV (always 0x00)
                        # Fourth byte is ATYP, see above for reference
                        header = b'\x05\x00\x00\x04'
                    else:
                        header = b'\x05\x00\x00\x01'
                    addr_to_send = socket.inet_pton(self._local_sock.family,
                                                    addr)
                    port_to_send = struct.pack('>H', port)
                    self._write_to_sock(header + addr_to_send + port_to_send,
                                        self._local_sock)
                    self._stage = STAGE_UDP_ASSOC
                    # just wait for the client to disconnect
                    return
                elif cmd == CMD_CONNECT:
                    # just trim VER CMD RSV
                    data = data[3:]
                else:
                    self._logging.error('U[%d] Unknown command %d',
                                        self._config['server_port'], cmd)
                    self.destroy()
                    return

            header_result = parse_header(data)
            if header_result is None:
                raise Exception(
                    'U[%d] TCP Can not parse header' %
                    self._config['server_port'])

            addrtype, remote_addr, remote_port, header_length = header_result
            if self._config['firewall_ports'] and self._config['server_port'] not in self._config['firewall_trusted']:
                # Firewall enabled
                if (self._config['firewall_mode'] == 'blacklist') == \
                        (remote_port in self._config['firewall_ports']):
                    # Remote port blocked by firewall, end this connection
                    self._logging.warning(
                        'U[%d] TCP PORT BANNED: RP[%d] A[%s-->%s]' %
                        (self._config['server_port'], remote_port, addr, common.to_str(remote_addr)))
                    return

            if self._config['relay_info']:
                relay_addr = self._config['relay_info']['address']
                relay_port = self._config['relay_info']['port']
                self._logging.info(
                    'U[%d] TCP CONN: WITH RELAY[%s:%d] A[%s-->%s:%d]' % (
                        self._config['server_port'], relay_addr, relay_port,
                        addr, common.to_str(remote_addr), remote_port
                    ))
                # It is in relay mode - remote_addr is replaced with the one
                # defined in relay_info
                remote_addr = relay_addr
                remote_port = relay_port
            else:
                if self._is_local:
                    self._logging.info('U[%d] TCP CONN: DEST[%s:%d]' % (
                        self._config['server_port'],
                        common.to_str(remote_addr), remote_port
                    ))
                else:
                    self._logging.info('U[%d] TCP CONN: A[%s-->%s:%d]' % (
                        self._config['server_port'], addr,
                        common.to_str(remote_addr), remote_port
                    ))

            self._remote_address = (common.to_str(remote_addr), remote_port)
            # pause reading
            self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            self._stage = STAGE_DNS
            if self._is_local:
                # forward address to remote
                self._write_to_sock((b'\x05\x00\x00\x01'
                                     b'\x00\x00\x00\x00\x10\x10'),
                                    self._local_sock)
                data_to_send = self._cryptor.encrypt(data)
                self._data_to_write_to_remote.append(data_to_send)
                # note that here may go into _handle_dns_resolved directly
                self._dns_resolver.resolve(self._chosen_server[0],
                                           self._handle_dns_resolved)
            else:
                if self._config['relay_info']:
                    self._data_to_write_to_remote.append(original_data)
                elif len(data) > header_length:
                    self._data_to_write_to_remote.append(data[header_length:])
                # note that here may go into _handle_dns_resolved directly
                self._dns_resolver.resolve(remote_addr,
                                           self._handle_dns_resolved)
        except Exception as e:
            self._log_error(e)
            if self._config['verbose']:
                traceback.print_exc()
            self.destroy()

    def _create_remote_socket(self, ip, port):
        addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM,
                                   socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("TCP getaddrinfo failed for %s:%d" % (ip, port))
        af, socktype, proto, canonname, sa = addrs[0]
        if self._forbidden_iplist:
            if common.to_str(sa[0]) in self._forbidden_iplist:
                raise Exception(
                    'U[%d] IP %s is in forbidden list, rejected' %
                    (self._config['server_port'],
                     common.to_str(
                        sa[0])))
        remote_sock = socket.socket(af, socktype, proto)
        self._remote_sock = remote_sock
        self._fd_to_handlers[remote_sock.fileno()] = self
        remote_sock.setblocking(False)
        remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        return remote_sock

    @shell.exception_handle(self_=True)
    def _handle_dns_resolved(self, result, error):
        if error:
            addr, port = self._local_sock.getpeername()[:2]
            self._logging.error('%s when handling connection from %s:%d' %
                                (error, addr, port))
            self.destroy()
            return
        if not (result and result[1]):
            self.destroy()
            return

        ip = result[1]
        self._stage = STAGE_CONNECTING
        remote_addr = ip
        if self._config['relay_info']:
            remote_port = self._config['relay_info']['port']
        elif self._is_local:
            remote_port = self._chosen_server[1]
        else:
            remote_port = self._remote_address[1]

        if self._is_local and self._config['fast_open']:
            # for fastopen:
            # wait for more data arrive and send them in one SYN
            # we don't have to wait for remote since it's not
            # created
            self._update_stream(STREAM_UP, WAIT_STATUS_READING)
            # TODO when there is already data in this packet
        else:
            # else do connect
            remote_sock = self._create_remote_socket(remote_addr,
                                                     remote_port)
            try:
                remote_sock.connect((remote_addr, remote_port))
            except (OSError, IOError) as e:
                if eventloop.errno_from_exception(e) == \
                        errno.EINPROGRESS:
                    pass
            self._loop.add(remote_sock,
                           eventloop.POLL_ERR | eventloop.POLL_OUT,
                           self._server)
            self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
            self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)

    def _handle_stage_stream(self, data, original_data):
        if self._is_local:
            data = self._cryptor.encrypt(data)
        if self._config['relay_info']:
            self._write_to_sock(original_data, self._remote_sock)
        else:
            self._write_to_sock(data, self._remote_sock)

    def _check_auth_method(self, data):
        # Greeting from client (socks5 method selection header):
        # +-----------------+-----+----------+---------+
        # | name            | VER | NMETHODS | METHODS |
        # +-----------------+-----+----------+---------+
        # | number of bytes | 1   | 1        | 1-255   |
        # +-----------------+-----+----------+---------+
        #
        # NMETHODS: 'number of methods supported by client'
        #
        # Method list:
        # X’00’ NO AUTHENTICATION REQUIRED
        # X’01’ GSSAPI
        # X’02’ USERNAME/PASSWORD
        # X’03’ to X’7F’ IANA ASSIGNED
        # X’80’ to X’FE’ RESERVED FOR PRIVATE METHODS
        # X’FF’ NO ACCEPTABLE METHODS
        #
        # Currently, only socks5 with NO_AUTH (i.e. X'00') is supported
        if len(data) < 3:
            self._logging.warning('method selection header too short')
            raise BadSocksHeader
        socks_version = common.ord(data[0])
        if socks_version != 5:
            self._logging.warning('unsupported SOCKS protocol version ' +
                                  str(socks_version))
            raise BadSocksHeader
        nmethods = common.ord(data[1])
        if nmethods < 1 or len(data) != nmethods + 2:
            self._logging.warning('NMETHODS and number of METHODS mismatch')
            raise BadSocksHeader
        noauth_exist = False
        for method in data[2:]:
            if common.ord(method) == METHOD_NOAUTH:
                noauth_exist = True
                break
        if not noauth_exist:
            self._logging.warning('none of SOCKS METHOD\'s '
                                  'requested by client is supported')
            raise NoAcceptableMethods

    def _handle_stage_init(self, data):
        try:
            self._check_auth_method(data)
        except BadSocksHeader:
            self.destroy()
            return
        except NoAcceptableMethods:
            # Reply to client: No acceptable method, and terminate session
            self._write_to_sock(b'\x05\xff', self._local_sock)
            self.destroy()
            return

        # Reply to client: Using socks version 5, with NO_AUTH as method
        self._write_to_sock(b'\x05\00', self._local_sock)
        self._stage = STAGE_ADDR

    def _on_local_read(self):
        # handle all local read events and dispatch them to methods for
        # each stage
        if not self._local_sock:
            return
        is_local = self._is_local
        data = None
        if is_local:
            buf_size = UP_STREAM_BUF_SIZE
        else:
            buf_size = DOWN_STREAM_BUF_SIZE
        try:
            data = self._local_sock.recv(buf_size)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in \
                    (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
        self._update_activity(len(data))
        if is_local:
            original_data = None
        else:
            if self._config['relay_info']:
                original_data = data
            else:
                original_data = None
            data = self._cryptor.decrypt(data)
            if not data and not self._config['relay_info']:
                # Empty data will also be relayed to the remote server
                return
        if self._stage == STAGE_STREAM:
            self._handle_stage_stream(data, original_data)
        elif is_local and self._stage == STAGE_INIT:
            # jump over socks5 init
            if self._is_tunnel:
                self._handle_stage_addr(data, None)
            else:
                self._handle_stage_init(data)
        elif self._stage == STAGE_CONNECTING:
            self._handle_stage_connecting(data, original_data)
        elif (is_local and self._stage == STAGE_ADDR) or \
                (not is_local and self._stage == STAGE_INIT):
            self._handle_stage_addr(data, original_data)

    def _on_remote_read(self):
        # handle all remote read events
        data = None
        if self._is_local or self._config['relay_info']:
            buf_size = UP_STREAM_BUF_SIZE
        else:
            buf_size = DOWN_STREAM_BUF_SIZE
        try:
            data = self._remote_sock.recv(buf_size)

        except socket.error as err:
            error_no = err.args[0]
            if sys.platform == "win32":
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK, errno.WSAEWOULDBLOCK):
                    return
            elif error_no in (errno.EAGAIN, errno.EINPROGRESS,
                              errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
        self._update_activity(len(data))
        if self._is_local:
            data = self._cryptor.decrypt(data)
        elif not self._config['relay_info']:
            data = self._cryptor.encrypt(data)
        try:
            # Relayed data will be sent as-is
            self._write_to_sock(data, self._local_sock)
        except Exception as e:
            shell.print_exception(e)
            if self._config['verbose']:
                traceback.print_exc()
            # TODO use logging when debug completed
            self.destroy()

    def _on_local_write(self):
        # handle local writable event
        if self._data_to_write_to_local:
            data = b''.join(self._data_to_write_to_local)
            self._data_to_write_to_local = []
            self._write_to_sock(data, self._local_sock)
        else:
            self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)

    def _on_remote_write(self):
        # handle remote writable event
        self._stage = STAGE_STREAM
        if self._data_to_write_to_remote:
            data = b''.join(self._data_to_write_to_remote)
            self._data_to_write_to_remote = []
            self._write_to_sock(data, self._remote_sock)
        else:
            self._update_stream(STREAM_UP, WAIT_STATUS_READING)

    def _on_local_error(self):
        self._logging.debug('got local error')
        if self._local_sock:
            self._logging.error(
                'U[%d] %s' %
                (self._config['server_port'],
                 eventloop.get_sock_error(
                    self._local_sock)))
        self.destroy()

    def _on_remote_error(self):
        self._logging.debug('got remote error')
        if self._remote_sock:
            self._logging.error(
                'U[%d] %s' %
                (self._config['server_port'],
                 eventloop.get_sock_error(
                    self._remote_sock)))
        self.destroy()

    @shell.exception_handle(self_=True, destroy=True)
    def handle_event(self, sock, event):
        # handle all events in this handler and dispatch them to methods
        if self._stage == STAGE_DESTROYED:
            self._logging.debug('ignore handle_event: destroyed')
            return
        # order is important
        if sock == self._remote_sock:
            if event & eventloop.POLL_ERR:
                self._on_remote_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_remote_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_remote_write()
        elif sock == self._local_sock:
            if event & eventloop.POLL_ERR:
                self._on_local_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_local_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_local_write()
        else:
            self._logging.warning('unknown socket')

    def _log_error(self, e):
        if self._local_sock:
            addr, port = self._local_sock.getpeername()[:2]
            self._logging.error(
                'U[%d] %s when handling connection from %s:%d' %
                (self._config['server_port'], e, addr, port))
        else:
            self._logging.error(
                'U[%d] Unknown TCP error occurred' %
                self._config['server_port'])

    def destroy(self):
        # destroy the handler and release any resources
        # promises:
        # 1. destroy won't make another destroy() call inside
        # 2. destroy releases resources so it prevents future call to destroy
        # 3. destroy won't raise any exceptions
        # if any of the promises are broken, it indicates a bug has been
        # introduced! mostly likely memory leaks, etc
        if self._stage == STAGE_DESTROYED:
            # this couldn't happen
            self._logging.debug('already destroyed')
            return
        self._stage = STAGE_DESTROYED
        if self._remote_address:
            self._logging.debug('destroy: %s:%d' %
                                self._remote_address)
        else:
            self._logging.debug('destroy')
        if self._remote_sock:
            self._logging.debug('destroying remote')
            self._loop.remove(self._remote_sock)
            del self._fd_to_handlers[self._remote_sock.fileno()]
            self._remote_sock.close()
            self._remote_sock = None
        if self._local_sock:
            self._logging.debug('destroying local')
            self._loop.remove(self._local_sock)
            del self._fd_to_handlers[self._local_sock.fileno()]
            self._local_sock.close()
            self._local_sock = None
        self._dns_resolver.remove_callback(self._handle_dns_resolved)
        self._server.remove_handler(self)


class TCPRelay(object):

    def __init__(self, config, dns_resolver, is_local, stat_callback=None):
        self._logging = TCPLogging()
        self._config = config
        self._is_local = is_local
        self._dns_resolver = dns_resolver
        self._closed = False
        self._eventloop = None
        self._fd_to_handlers = {}
        self._is_tunnel = False

        self._timeout = config['timeout']
        self._timeouts = []  # a list for all the handlers
        # we trim the timeouts once a while
        self._timeout_offset = 0   # last checked position for timeout
        self._handler_to_timeouts = {}  # key: handler value: index in timeouts

        if is_local:
            listen_addr = config['local_address']
            listen_port = config['local_port']
        else:
            listen_addr = config['server']
            listen_port = config['server_port']
        self._listen_port = listen_port

        addrs = socket.getaddrinfo(listen_addr, listen_port, 0,
                                   socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("TCP getaddrinfo failed for %s:%d" %
                            (listen_addr, listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(sa)
        server_socket.setblocking(False)
        if self._config['fast_open']:
            try:
                server_socket.setsockopt(socket.SOL_TCP, 23, 5)
            except socket.error:
                self._logging.warning(
                    'Fast open is not available, automatically turned off')
                self._config['fast_open'] = False
        server_socket.listen(1024)
        self._server_socket = server_socket
        self._stat_callback = stat_callback

    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop
        self._eventloop.add(self._server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR, self)
        self._eventloop.add_periodic(self.handle_periodic)

    def remove_handler(self, handler):
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]

    def update_activity(self, handler, data_len):
        if data_len and self._stat_callback:
            self._stat_callback(self._listen_port, data_len)

        # set handler to active
        now = int(time.time())
        if now - handler.last_activity < eventloop.TIMEOUT_PRECISION:
            # thus we can lower timeout modification frequency
            return
        handler.last_activity = now
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
        length = len(self._timeouts)
        self._timeouts.append(handler)
        self._handler_to_timeouts[hash(handler)] = length

    def _sweep_timeout(self):
        # tornado's timeout memory management is more flexible than we need
        # we just need a sorted last_activity queue and it's faster than heapq
        # in fact we can do O(1) insertion/remove so we invent our own
        if self._timeouts:
            self._logging.log(shell.VERBOSE_LEVEL, 'sweeping timeouts')
            now = time.time()
            length = len(self._timeouts)
            pos = self._timeout_offset
            while pos < length:
                handler = self._timeouts[pos]
                if handler:
                    if now - handler.last_activity < self._timeout:
                        break
                    else:
                        if handler.remote_address:
                            self._logging.warning('timed out: %s:%d' %
                                                  handler.remote_address)
                        else:
                            self._logging.warning('timed out')
                        handler.destroy()
                        self._timeouts[pos] = None  # free memory
                        pos += 1
                else:
                    pos += 1
            if pos > TIMEOUTS_CLEAN_SIZE and pos > length >> 1:
                # clean up the timeout queue when it gets larger than half
                # of the queue
                self._timeouts = self._timeouts[pos:]
                for key in self._handler_to_timeouts:
                    self._handler_to_timeouts[key] -= pos
                pos = 0
            self._timeout_offset = pos

    def handle_event(self, sock, fd, event):
        # handle events and dispatch to handlers
        if sock:
            self._logging.log(shell.VERBOSE_LEVEL, 'fd %d %s', fd,
                              eventloop.EVENT_NAMES.get(event, event))
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                # TODO
                raise Exception('server_socket error')
            try:
                self._logging.debug('accept')
                conn = self._server_socket.accept()
                TCPRelayHandler(self, self._fd_to_handlers,
                                self._eventloop, conn[0], self._config,
                                self._dns_resolver, self._is_local)
            except socket.error as err:
                error_no = err.args[0]
                if sys.platform == "win32":
                    if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                    errno.EWOULDBLOCK, errno.WSAEWOULDBLOCK):
                        return
                elif error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                  errno.EWOULDBLOCK):
                    return
                else:
                    shell.print_exception(err)
        else:
            if sock:
                handler = self._fd_to_handlers.get(fd, None)
                if handler:
                    handler.handle_event(sock, event)
            else:
                self._logging.warning('poll removed fd')

    def handle_periodic(self):
        if self._closed:
            if self._server_socket:
                self._eventloop.remove(self._server_socket)
                self._server_socket.close()
                self._server_socket = None
                self._logging.info('TCP port %d closed', self._listen_port)
            if not self._fd_to_handlers:
                self._logging.info('stopping')
                self._eventloop.stop()
        self._sweep_timeout()

    def close(self, next_tick=False):
        self._logging.debug('TCP close')
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            self._server_socket.close()
            for handler in list(self._fd_to_handlers.values()):
                handler.destroy()
