# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# February 24 2018, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2018, Deutsche Telekom AG.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
import argparse
import datetime
import logging
import os
import platform
import socket
# import sys
# import time
from lxml import etree
from netconf import error, server, util
from netconf import nsmap_add, NSMAP
from prompt_toolkit import prompt
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter

nc_completer = WordCompleter(['exit','raise_alarm'], ignore_case=True)

data_path = os.path.join(os.path.dirname(__file__), 'data')

ns_file_map = {}
ns_file_map['acc-devm'] = os.path.join(data_path, 'acc-devm-data.xml')

# nsmap_add("sys", "urn:ietf:params:xml:ns:yang:ietf-system")
for ns in ns_file_map:
    nsmap_add(ns, ':'.join(("urn:ccsa:yang", ns)))

# nsmap_add('ncEvent', 'urn:ietf:params:xml:ns:netconf:notification:1.0')

logger = logging.getLogger(__name__)

def date_time_string(dt):
    tz = dt.strftime("%z")
    s = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
    if tz:
        s += " {}:{}".format(tz[:-2], tz[-2:])
    return s

class SystemServer(object):
    def __init__(self, port, host_key, auth, debug):
        self.server = server.NetconfSSHServer(auth, self, port, host_key, debug)
        self.ns_of_filter = []

    def close(self):
        self.server.close()

    def nc_append_capabilities(self, capabilities):  # pylint: disable=W0613
        """The server should append any capabilities it supports to capabilities"""
        util.subelm(capabilities, "capability").text = "urn:ietf:params:netconf:capability:xpath:1.0"
        util.subelm(capabilities, "capability").text = NSMAP["ncEvent"]
        # util.subelm(capabilities, "capability").text = NSMAP["acc-devm"]

    # subtree: https://tools.ietf.org/html/rfc6241#section-6.4
    def gen_xpath_from_subtree(self, subtree_node, xpath_parent='', xpath_list=[]):
        children = subtree_node.getchildren()
        xpath_cur = '/'.join((xpath_parent, subtree_node.tag))
        if len(children) == 0:  #leaf
            xpath_list.append(xpath_cur)
        else:
            for child in children:
                self.gen_xpath_from_subtree(child, xpath_cur, xpath_list)

    # https://blog.csdn.net/yiluochenwu/article/details/23515923
    def pre_process_filter(self, filter_or_none):
        if filter_or_none is None:
            return

        if 'type' not in filter_or_none.attrib:
            return
        
        if filter_or_none.attrib['type'] == 'subtree':
            if len(filter_or_none.getchildren()) == 0:
                return

            # convert subtree to xpath
            xpath_list = []
            for node in filter_or_none.getchildren():
                self.gen_xpath_from_subtree(node, '', xpath_list)
            xpathstr = '|'.join(xpath_list)

            # replace ns to prefix
            for ns in NSMAP:
                if NSMAP[ns] in xpathstr:
                    self.ns_of_filter.append(ns)
                    xpathstr = xpathstr.replace('{' + NSMAP[ns] + '}', ns + ':')
            logger.debug("Xpath from substring is: %s", xpathstr)

            filter_or_none.clear()
            if '/{http://' in xpathstr:
                logger.debug("Namespace not supported.")
            else:
                filter_or_none.attrib['type'] = 'xpath'
                filter_or_none.attrib['select'] = xpathstr

        elif filter_or_none.attrib['type'] == 'xpath':
            if filter_or_none.attrib['select'] is not None:
                for ns in NSMAP:
                    if ns in filter_or_none.attrib['select']:
                        self.ns_of_filter.append(ns)

    def rpc_get(self, session, rpc, filter_or_none):  # pylint: disable=W0613
        logger.debug("Filter of rpc_get is: %s", filter_or_none.attrib if filter_or_none is not None else 'None')
        self.ns_of_filter.clear()
        self.pre_process_filter(filter_or_none)
        logger.debug("Filter of rpc_get after process is: %s", filter_or_none.attrib if filter_or_none is not None else 'None')
        logger.debug("Namespace in Filter is: %s", self.ns_of_filter)

        # lxml:  http://yshblog.com/blog/151
        data = util.elm("data")
        if len(self.ns_of_filter) > 0:
            data = etree.parse(ns_file_map[self.ns_of_filter[0]]).getroot()

        return util.filter_results(rpc, data, filter_or_none, self.server.debug)

    def rpc_get_config(self, session, rpc, source_elm, filter_or_none):  # pylint: disable=W0613
        return self.rpc_get(session, rpc, filter_or_none)
    
    def rpc_edit_config(self, session, rpc, *params):  # pylint: disable=W0613
        data = util.elm("ok")
        return util.filter_results(rpc, data, None)

    def rpc_system_restart(self, session, rpc, *params):
        raise error.AccessDeniedAppError(rpc)

    def rpc_system_shutdown(self, session, rpc, *params):
        raise error.AccessDeniedAppError(rpc)

    def send_notification(self, data, *params):
        msg = etree.Element("{{{}}}notification".format(NSMAP['ncEvent']))
        node_event_time = util.leaf_elm('eventTime', date_time_string(datetime.datetime.now()))
        msg.append(node_event_time)
        msg.append(data)
        msg_unicode = etree.tounicode(msg, pretty_print=True)
        logger.debug("notification msg is:\n%s", str(msg_unicode))
        for socket in self.server.sockets:
            if socket.running is False:
                continue
            for session in socket.sessions:
                if session.session_open is False:
                    continue
                logger.debug("Sending to client, session id: %d, ip:%s, port:%d",
                    session.session_id, socket.client_addr[0], socket.client_addr[1])
                session.send_message(msg_unicode)
        return

    def raise_alarm(self, *params):
        logger.debug("raise_alarm starting...")
        data = etree.parse(os.path.join(data_path, 'raise-alarm.xml')).getroot()
        self.send_notification(data)
        logger.debug("raise_alarm end.")
        return


def startMyServer():
    # logging: https://cloud.tencent.com/developer/article/1354396
    debug = True
    level=logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, filename='server.log', filemode='w', format='%(asctime)s %(levelname)s:%(name)s(L%(lineno)d): %(message)s')

    host_key = os.path.join(os.path.dirname(__file__), "server-key")
    auth = server.SSHUserPassController(username='who', password='Who_1234')
    s = SystemServer(830, host_key, auth, debug)

    if s.server:
        print('Server started.')
        serverIsRunning = True
        while True:
            # time.sleep(5)
            #print(s.server.sockets, len(s.server.sockets))  #当前已经建链的socket
            if s.server.thread.isAlive():
                if not serverIsRunning:
                    print('Server is running.')
                    serverIsRunning = True
            else:
                print('Server stopped. Restarting...')
                # s.close()
                serverIsRunning = False
                s = SystemServer(830, host_key, auth, debug)

            cli = prompt('>', 
                        history=FileHistory('history.txt'),
                        auto_suggest=AutoSuggestFromHistory(),
                        completer=nc_completer,
                        )
            if cli == 'exit':
                return
            elif cli in nc_completer.words:
                # locals()['s.' + cli]()
                getattr(s, cli)()
            else:
                print('Not supported!')

if __name__ == "__main__":
    #main()
    startMyServer()

