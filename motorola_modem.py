#!/usr/bin/python3
#
# Modem client for Motorola MB8611 (and maybe others)
#
# Copyright 2022 Dan Smith <dsmith+mb8611@danplanet.com>
#
# Adapted from:
# https://github.com/aclytle/Motorola-Modem-Reboot/blob/master/modem_reboot.py

import argparse
import datetime
import hmac
import sys
import time

import pprint
import prettytable
import requests
from urllib3.exceptions import InsecureRequestWarning


def ns(op):
    return '"http://purenetworks.com/HNAP1/%s"' % op


def hmac_md5(key, msg):
    return hmac.new(key, msg, digestmod='MD5').hexdigest().upper()


class MotorolaClient:
    ACTIONS = ['status', 'connection', 'channels', 'reboot',
               'uptime', 'lag']

    def __init__(self, host, username, password, https=True, verify=False):
        self.s = requests.Session()
        self.s.verify = verify
        self.url = '%s://%s/HNAP1/' % (https and 'https' or 'http',
                                       host)
        self.username = username
        self.password = password
        # These are resolved later when generate_keys() is called
        self.private = b''
        self.passkey = ''

    def generate_keys(self, challenge, pubkey):
        self.private = hmac_md5(pubkey.encode() + self.password.encode(),
                                challenge.encode()).encode()
        self.passkey = hmac_md5(self.private, challenge.encode())

    def hnap_auth(self, method):
        now = str(int(time.time()) * 1000)
        auth_key = now + ns(method)
        return '%s %s' % (hmac_md5(self.private, auth_key.encode()), now)

    def request(self, method, **params):
        """Perform an authenticated request and get the result."""
        headers = {'HNAP_AUTH': self.hnap_auth(method),
                   'SOAPAction': ns(method)}
        payload = {method: params}
        r = self.s.post(self.url, headers=headers, json=payload)
        r.raise_for_status()
        return r.json()['%sResponse' % method]

    def login(self):
        """Login to the modem.

        This involves a dance of requesting a challenge and using that to
        craft the actual authentication message.
        """
        lr_resp = self.request('Login',
                               Action='request',
                               Username=self.username,
                               LoginPassword='',
                               Captcha='',
                               PrivateLogin='LoginPassword')

        if lr_resp['LoginResult'] != 'OK':
            raise Exception('Login is disabled')

        self.generate_keys(lr_resp['Challenge'], lr_resp['PublicKey'])
        self.s.cookies.set('uid', lr_resp['Cookie'])
        self.s.cookies.set('PrivateKey', self.private.decode())

        resp = self.request('Login',
                            Action='login',
                            Username=self.username,
                            LoginPassword=self.passkey,
                            Captcha='',
                            PrivateLogin='LoginPassword')
        return resp['LoginResult'] == 'OK'

    def status(self):
        """Returns software version status."""
        return self.request('GetMultipleHNAPs',
                            GetMotoStatusSoftware='',
                            GetMotoStatusXXX='')

    def connection(self):
        """Returns some information about the connection."""
        return self.request('GetMultipleHNAPs',
                            GetMotoStatusStartupSequence='',
                            GetMotoStatusConnectionInfo='',
                            GetMotoLagStatus='')

    def channels(self):
        """Returns up/downstream channel info.

        Note this takes a while for the modem to generate, which is
        why it is broken out from the above.
        """
        return self.request('GetMultipleHNAPs',
                            GetMotoStatusDownstreamChannelInfo='',
                            GetMotoStatusUpstreamChannelInfo='')

    def reboot(self):
        """Trigger a reboot.

        Returns the response action, if successful or an error message.
        """
        resp = self.request('SetStatusSecuritySettings',
                            MotoStatusSecurityAction='1',
                            MotoStatusSecXXX='XXX')
        if resp['SetStatusSecuritySettingsResult'] == 'UN-AUTH':
            raise Exception('Modem reports insufficient authorization')

        if resp['SetStatusSecuritySettingsResult'] == 'OK':
            return resp['SetStatusSecuritySettingsAction']
        else:
            return 'Unknown response from modem'

    def lag(self):
        r = self.connection()
        return int(r['GetMotoLagStatusResponse']['MotoLagCurrentStatus'])

    def uptime(self):
        r = self.connection()
        ut = r['GetMotoStatusConnectionInfoResponse']['MotoConnSystemUpTime']
        ndays, days, time = ut.split(' ')
        hours = int(time[0:2])
        minutes = int(time[4:6])
        seconds = int(time[8:10])
        td = datetime.timedelta(days=int(ndays), hours=hours, minutes=minutes,
                                seconds=seconds)
        return str(td)

    def connstatus(self):
        r = self.connection()
        startup = r['GetMotoStatusStartupSequenceResponse']
        return {
            'Upstream': startup['MotoConnBootStatus'],
            'Downstream': startup['MotoConnBootStatus'],
        }

    def events(self):
        resp = self.request('GetMultipleHNAPs',
                            GetMotoStatusLog='',
                            GetMotoStatusLogXXX='')
        l = resp['GetMotoStatusLogResponse']['MotoStatusLogList'].split('}-{')

        pt = prettytable.PrettyTable(['Time', 'Level', 'Message'])
        for log in l:
            row = log.split('^')
            stamp = ' '.join([row[0], row[1]])
            level = row[2]
            msg = row[3]
            pt.add_row([stamp.strip(), level.strip(), msg.strip()])

        print(pt)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--username', default='admin')
    p.add_argument('--password', default='motorola')
    p.add_argument('--host', default='192.168.100.1')
    p.add_argument('--noauth', action='store_true',
                   help='Do not attempt to login before performing action.')
    p.add_argument('action',
                   help=('One of status,connection,channels,reboot,events,'
                         'lag,connstatus,uptime'))
    return p.parse_args()


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    args = parse_args()
    c = MotorolaClient(args.host, args.username, args.password)
    # NOTE: Login is not specifically required for most readonly
    # operations, apparently, but we might as well always do it.
    if not args.noauth:
        if not c.login():
            print('Login failed')
            sys.exit(1)
    r = getattr(c, args.action)()
    if isinstance(r, (str, int)):
        print(r)
    else:
        pprint.pprint(r)
