#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 mengskysama
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

import logging
import time
import socket
import config
import json
import sys

if config.API_ENABLED:
    if sys.version_info >= (3, 0):
        # If using python 3, use urllib.parse and urllib.request instead of
        # urllib and urllib2
        from urllib.parse import urlencode
        from urllib.request import Request, urlopen
    else:
        from urllib import urlencode
        from urllib2 import Request, urlopen
else:
    import cymysql


class DbTransfer(object):
    @staticmethod
    def send_command(cmd):
        data = ''
        try:
            cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cli.settimeout(2)
            cli.sendto(
                cmd.encode(),
                ('%s' %
                 config.MANAGER_BIND_IP,
                 config.MANAGER_PORT))
            data, addr = cli.recvfrom(1500)
            cli.close()
            # TODO: bad way solve timed out
            time.sleep(0.05)
        except Exception as e:
            if config.SS_VERBOSE:
                import traceback
                traceback.print_exc()
            logging.warning('Exception thrown when sending command: %s' % e)
        return data

    @staticmethod
    def get_servers_transfer():
        DbTransfer.verbose_print('request transfer count from manager - start')
        dt_transfer = {}
        cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cli.settimeout(2)
        cli.sendto(
            b'transfer: {}',
            (config.MANAGER_BIND_IP,
             config.MANAGER_PORT))
        while True:
            data, addr = cli.recvfrom(1500)
            if data == b'e':
                break
            data = json.loads(data)
            dt_transfer.update(data)
        cli.close()
        DbTransfer.verbose_print('request transfer count from manager - done')
        return dt_transfer

    @staticmethod
    def verbose_print(msg):
        if config.SS_VERBOSE:
            logging.info(msg)

    @staticmethod
    def http_post(url, data):
        data = urlencode(data).encode()
        req = Request(url, data)
        response = urlopen(req)
        response_data = response.read()
        response.close()
        DbTransfer.verbose_print('%s - %s - %s' % (url, data, response_data))
        return response_data

    @staticmethod
    def start_server(row, restart=False):
        if restart:
            DbTransfer.send_command('remove: {"server_port":%d}' % row[0])
            time.sleep(0.1)
        DbTransfer.send_command(
            'add: {"server_port": %d, "password":"%s", "method":"%s", "email":"%s", "relay_info":"%s"}' %
            (row[0], row[4], row[7], row[8], row[10]))

    @staticmethod
    def del_server_out_of_bound_safe(rows):
        for row in rows:
            server = json.loads(DbTransfer.send_command(
                'stat: {"server_port":%s}' % row[0]))
            if server['stat'] != 'ko':
                # server exists and is running
                if row[5] == 0 or row[6] == 0:
                    # stop disabled or switched-off user
                    logging.info(
                        'U[%d] Server has been stopped: user is disabled' %
                        row[0])
                    DbTransfer.send_command(
                        'remove: {"server_port":%d}' % row[0])
                elif row[1] + row[2] >= row[3]:
                    # stop user that exceeds data transfer limit
                    logging.info(
                        'U[%d] Server has been stopped: data transfer limit exceeded' %
                        row[0])
                    DbTransfer.send_command(
                        'remove: {"server_port":%d}' % row[0])
                elif server['password'] != row[4]:
                    # password changed
                    logging.info(
                        'U[%d] Server is restarting: password is changed' %
                        row[0])
                    DbTransfer.start_server(row, True)
                elif eval(server['relay_info']) != row[10]:
                    logging.info(
                        'U[%d] Server is restarting: relay information has been changed' %
                        row[0])
                else:
                    if not config.SS_CUSTOM_METHOD:
                        row[7] = config.SS_METHOD
                    if server['method'] != row[7]:
                        # encryption method changed
                        logging.info(
                            'U[%d] Server is restarting: encryption method has been changed' %
                            row[0])
                        DbTransfer.start_server(row, True)
            else:
                if row[5] != 0 and row[6] != 0 and row[1] + row[2] < row[3]:
                    if not config.SS_CUSTOM_METHOD:
                        row[7] = config.SS_METHOD
                    DbTransfer.start_server(row)
                    if config.MANAGER_BIND_IP != '127.0.0.1':
                        if row[10]:
                            logging.info(
                                'U[%s] Server Started with password [%s] and method [%s], relaying to [%s]' %
                                (row[0], row[4], row[7], row[10]['address'] + ':' + row[10]['port']))
                        else:
                            logging.info(
                                'U[%s] Server Started with password [%s] and method [%s]' %
                                (row[0], row[4], row[7]))

    @staticmethod
    def thread_pull():
        socket.setdefaulttimeout(config.TIMEOUT)
        while True:
            try:
                if config.API_ENABLED:
                    rows = DbTransfer.pull_api_user()
                else:
                    rows = DbTransfer.pull_db_user()
                DbTransfer.del_server_out_of_bound_safe(rows)
            except Exception as e:
                if config.SS_VERBOSE:
                    import traceback
                    traceback.print_exc()
                logging.error('Except thrown while pulling user data:%s' % e)
            finally:
                time.sleep(config.CHECKTIME)

    @staticmethod
    def pull_api_relay_rules():
        # Relay function is not supported by the vanilla SS-Panel
        DbTransfer.verbose_print('api relay rules download - start')
        response = urlopen(config.API_URL + '/node/' + config.API_NODE_ID +
                           '/' + 'rules?key=' + config.API_PASS)
        # Data in format:
        # {'8388': {'address': 'somenode.example.com', 'port': '8388'}}
        response_data = json.load(response)
        response.close()
        DbTransfer.verbose_print('api relay rules download - end')
        return response_data

    @staticmethod
    def pull_api_user():
        if config.API_RELAY_MODE and config.API_RELAY_MODE != config.RELAY_ALL:
            rules = DbTransfer.pull_api_relay_rules()
            if config.API_RELAY_MODE == config.RELAY_ONLY and not rules:
                logging.info('relay-only mode is on and no users on list')
                return []

        DbTransfer.verbose_print('api user table download - start')
        # Node parameter is not included for the vanilla SS-Panel
        url = config.API_URL + '/users?key=' + \
            config.API_PASS + '&node=' + config.API_NODE_ID
        response = urlopen(url)
        response_data = json.load(response)
        response.close()
        rows = []
        for user in response_data['data']:
            if user['port'] in config.SS_SKIP_PORTS:
                DbTransfer.verbose_print('api skipped port %d' % user['port'])
            elif user.get('switch') == 0 or user['enable'] == 0:
                rows.append([
                    user['port'],
                    None, None, None, None,
                    user.get('switch'),
                    user['enable'],
                    None, None, None
                ])
            else:
                if config.API_RELAY_MODE == config.RELAY_DISABLED:
                    relay_info = None
                else:
                    # Relay mode is on, search in rules whether
                    # this user use relay
                    if config.API_RELAY_MODE == config.RELAY_ALL:
                        relay_info = {
                            'address': config.API_RELAY_ALL_TARGET,
                            'port': user['port']
                        }
                    elif str(user['port']) in rules:
                        relay_info = {
                            'address': rules[str(user['port'])]['address'],
                            'port': rules[str(user['port'])]['port']
                        }
                    else:
                        if config.API_RELAY_MODE == config.RELAY_ONLY:
                            # Since user is not on the list and the node is
                            # relay-only, the user will be set disabled even when
                            # it was enabled
                            user['enable'] = 0
                        relay_info = None

                rows.append([
                    user['port'],
                    user['u'],
                    user['d'],
                    user['transfer_enable'],
                    user['passwd'],
                    user['switch'],
                    user['enable'],
                    user['method'],
                    user['email'],
                    user['id'],
                    relay_info
                ])
        DbTransfer.verbose_print('api user table download - done')
        return rows

    @staticmethod
    def pull_db_user():
        DbTransfer.verbose_print('db user table download - start')
        string = ''
        for index in range(len(config.SS_SKIP_PORTS)):
            port = config.SS_SKIP_PORTS[index]
            DbTransfer.verbose_print('db skipped port %d' % port)
            if index == 0:
                string = ' WHERE `port`<>%d' % port
            else:
                string = '%s AND `port`<>%d' % (string, port)
        conn = cymysql.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USER,
            passwd=config.MYSQL_PASS,
            db=config.MYSQL_DB,
            charset='utf8')
        cur = conn.cursor()
        cur.execute(
            'SELECT port, u, d, transfer_enable, passwd, switch, enable, method, email FROM %s%s ORDER BY `port` ASC' %
            (config.MYSQL_USER_TABLE, string))
        rows = []
        for r in cur.fetchall():
            rows.append(list(r))
        # Release resources
        cur.close()
        conn.close()
        DbTransfer.verbose_print('db user table download - done')
        return rows

    @staticmethod
    def thread_push():
        socket.setdefaulttimeout(config.TIMEOUT)
        while True:
            try:
                dt_transfer = DbTransfer.get_servers_transfer()
                if config.API_ENABLED:
                    DbTransfer.push_api_user(dt_transfer)
                else:
                    DbTransfer.push_db_user(dt_transfer)
            except Exception as e:
                import traceback
                if config.SS_VERBOSE:
                    traceback.print_exc()
                logging.error('Except thrown while pushing user data:%s' % e)
            finally:
                time.sleep(config.SYNCTIME)

    @staticmethod
    def push_api_user(dt_transfer):
        # user data traffic statistics
        i = 0
        DbTransfer.verbose_print(
            'api upload: pushing transfer statistics - start')
        users = DbTransfer.pull_api_user()
        datalist = []
        for port in dt_transfer.keys():
            user = None
            for result in users:
                if str(result[0]) == port:
                    user = result[9]
                    break
            if not user:
                logging.warning('U[%s] User Not Found', port)
                server = json.loads(DbTransfer.get_instance().send_command(
                    'stat: {"server_port":%s}' % port))
                if server['stat'] != 'ko':
                    logging.info(
                        'U[%s] Server has been stopped: user is removed' %
                        port)
                    DbTransfer.send_command(
                        'remove: {"server_port":%s}' % port)
                continue
            DbTransfer.verbose_print(
                'U[%s] User ID Obtained:%s' %
                (port, user))
            tran = str(dt_transfer[port])
            datalist.append({'d': tran, 'node_id': config.API_NODE_ID, 'user_id': user, 'u': '0'})
            i += 1
        if config.API_BATCH_UPDATE:
            url = config.API_URL + '/nodes/' + str(config.API_NODE_ID) + '/traffic?key=' + config.API_PASS
            headers = {'Content-Type': 'application/json'}
            request = Request(url=url, headers=headers, data=json.dumps(datalist))
            response = urlopen(request)
            response.close()
        else:
            for data in datalist:
                url = config.API_URL + '/users/' + \
                  str(data['user_id']) + '/traffic?key=' + config.API_PASS
                DbTransfer.http_post(url, data)

        DbTransfer.verbose_print('api upload: pushing transfer statistics - done')

        # online user count
        DbTransfer.verbose_print(
            'api upload: pushing online user count - start')
        data = {'count': i}
        url = config.API_URL + '/nodes/' + config.API_NODE_ID + \
            '/online_count?key=' + config.API_PASS
        DbTransfer.http_post(url, data)
        DbTransfer.verbose_print(
            'api upload: pushing online user count - done')

        # load info
        DbTransfer.verbose_print('api upload: node status - start')
        url = config.API_URL + '/nodes/' + \
            config.API_NODE_ID + '/info?key=' + config.API_PASS
        f = open("/proc/loadavg")
        load = f.read().split()
        f.close()
        loadavg = load[0] + ' ' + load[1] + ' ' + \
            load[2] + ' ' + load[3] + ' ' + load[4]
        f = open("/proc/uptime")
        uptime = f.read().split()
        uptime = uptime[0]
        f.close()
        data = {'load': loadavg, 'uptime': uptime}
        DbTransfer.http_post(url, data)
        DbTransfer.verbose_print('api upload: node status - done')

    @staticmethod
    def push_db_user(dt_transfer):
        DbTransfer.verbose_print('db upload - start')
        query_head = 'UPDATE `user`'
        query_sub_when = ''
        query_sub_when2 = ''
        query_sub_in = None
        last_time = time.time()
        for port in dt_transfer.keys():
            query_sub_when += ' WHEN %s THEN `u`+%s' % (port, 0)  # all in d
            query_sub_when2 += ' WHEN %s THEN `d`+%s' % (
                port, dt_transfer[port])
            if query_sub_in is not None:
                query_sub_in += ',%s' % port
            else:
                query_sub_in = '%s' % port
        if query_sub_when == '':
            return
        query_sql = query_head + ' SET u = CASE port' + query_sub_when + \
            ' END, d = CASE port' + query_sub_when2 + \
            ' END, t = ' + str(int(last_time)) + \
            ' WHERE port IN (%s)' % query_sub_in
        # print query_sql
        conn = cymysql.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USER,
            passwd=config.MYSQL_PASS,
            db=config.MYSQL_DB,
            charset='utf8')
        cur = conn.cursor()
        cur.execute(query_sql)
        cur.close()
        conn.commit()
        conn.close()
        DbTransfer.verbose_print('db upload - done')
