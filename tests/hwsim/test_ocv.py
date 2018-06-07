# WPA2-Personal OCV tests
# Copyright (c) 2018, Mathy Vanhoef
#
# This software may be distributed under the terms of the BSD license.
# See README for more details

from remotehost import remote_compatible
import binascii
import logging
logger = logging.getLogger()
import struct

import hostapd
from wpasupplicant import WpaSupplicant
# FIXME: Just import * ...
from test_ap_psk import recv_eapol, send_eapol, build_eapol, pmk_to_ptk, reply_eapol, hapd_connected, build_eapol_key_3_4, aes_wrap, pad_key_data

#TODO: Refuse setting up AP with OCV but without MFP support
#TODO: Refuse to connect to AP that advertises OCV but not MFP
#TODO: Let them connect with *WRONG* parameters to detect failures
#TODO: Unexpected OCI to client that didn't negotiate it

def make_ocikde(op_class, channel, seg1_idx):
    WLAN_EID_VENDOR_SPECIFIC = 221
    RSN_KEY_DATA_OCI = "\x00\x0f\xac\x0d"

    data   = RSN_KEY_DATA_OCI + struct.pack("<BBB", op_class, channel, seg1_idx)
    ocikde = struct.pack("<BB", WLAN_EID_VENDOR_SPECIFIC, len(data)) + data

    return ocikde

def ocv_setup_ap(apdev, params):
    ssid = "test-wpa2-ocv"
    passphrase = "qwertyuiop"
    params.update(hostapd.wpa2_params(ssid=ssid, passphrase=passphrase))
    hapd = hostapd.add_ap(apdev, params)
    return hapd, ssid, passphrase

def reset_ap(apdev):
    hapd = hostapd.HostapdGlobal()
    hapd.remove(apdev['ifname'])

class APConnection:
    def __init__(self):
        self.hapd = None
        self.addr = None
        self.rsne = None
        self.kck  = None
        self.msg  = None
        self.anonce = None
        self.snonce = None

    def __init__(self, apdev, dev, params):
        freq = params.pop("freq")
        sta_ocv = params.pop("sta_ocv", "1")
        ssid = "test-wpa2-ocv"
        passphrase = "qwertyuiop"
        psk = "c2c6c255af836bed1b3f2f1ded98e052f5ad618bb554e2836757b55854a0eab7"
        params.update(hostapd.wpa2_params(ssid=ssid, passphrase=passphrase))
        params['wpa_pairwise_update_count'] = "10"

        self.hapd = hostapd.add_ap(apdev, params)
        self.hapd.request("SET ext_eapol_frame_io 1")
        dev.request("SET ext_eapol_frame_io 1")

        bssid = apdev['bssid']
        pmk = binascii.unhexlify("c2c6c255af836bed1b3f2f1ded98e052f5ad618bb554e2836757b55854a0eab7")

        if sta_ocv != "0":
            self.rsne = binascii.unhexlify("301a0100000fac040100000fac040100000fac0280400000000fac06")
        else:
            self.rsne = binascii.unhexlify("301a0100000fac040100000fac040100000fac0280000000000fac06")
        self.snonce = binascii.unhexlify('1111111111111111111111111111111111111111111111111111111111111111')

        dev.connect(ssid, raw_psk=psk, scan_freq=freq, ocv=sta_ocv, ieee80211w="1", wait_connect=False)
        self.addr = dev.p2p_interface_addr()

        # Wait for EAPOL-Key msg 1/4 from hostapd to determine when associated
        self.msg = recv_eapol(self.hapd)
        self.anonce = self.msg['rsn_key_nonce']
        (ptk, self.kck, kek) = pmk_to_ptk(pmk, self.addr, bssid, self.snonce,self.anonce)


    # hapd, addr, rsne, kck, msg, anonce, snonce
    def test_bad_oci(self, logmsg, op_class, channel, seg1_idx):
        logger.debug("Bad OCI element: " + logmsg)
        if op_class is None:
            ocikde = ""
        else:
            ocikde = make_ocikde(op_class, channel, seg1_idx)

        reply_eapol("2/4", self.hapd, self.addr, self.msg, 0x010a, self.snonce, self.rsne + ocikde, self.kck)
        self.msg = recv_eapol(self.hapd)
        if self.anonce != self.msg['rsn_key_nonce'] or self.msg["rsn_key_info"] != 138:
            raise Exception("Didn't receive retransmitted 1/4")

    def confirm_valid_oci(self, op_class, channel, seg1_idx):
        logger.debug("Valid OCI element to complete handshake")
        ocikde = make_ocikde(op_class, channel, seg1_idx)

        reply_eapol("2/4", self.hapd, self.addr, self.msg, 0x010a, self.snonce, self.rsne + ocikde, self.kck)
        self.msg = recv_eapol(self.hapd)
        if self.anonce != self.msg['rsn_key_nonce'] or self.msg["rsn_key_info"] != 5066:
            raise Exception("Didn't receive 3/4 in response to valid 2/4")

        reply_eapol("4/4", self.hapd, self.addr, self.msg, 0x030a, None, None, self.kck)
        hapd_connected(self.hapd)


@remote_compatible
def test_wpa2_ocv(dev, apdev):
    params = { "channel": "1", "ieee80211w": "2", "ocv": "1" }
    hapd, ssid, passphrase = ocv_setup_ap(apdev[0], params)
    for ocv in range(2):
        dev[0].connect(ssid, psk=passphrase, scan_freq="2412", ocv=str(ocv), ieee80211w="1")

@remote_compatible
def test_wpa2_ocv_5ghz(dev, apdev):
    params = { "hw_mode": "a", "channel": "40", "ieee80211w": "2", "country_code": "US", "ocv": "1" }
    hapd, ssid, passphrase = ocv_setup_ap(apdev[0], params)
    for ocv in range(2):
        dev[0].connect(ssid, psk=passphrase, scan_freq="5200", ocv=str(ocv), ieee80211w="1")

@remote_compatible
def test_wpa2_ocv_ht20(dev, apdev):
    params = { "channel": "6", "ieee80211n": "1", "ieee80211w": "1", "ocv": "1"}
    hapd, ssid, passphrase = ocv_setup_ap(apdev[0], params)
    for ocv in range(2):
        dev[0].connect(ssid, psk=passphrase, scan_freq="2437", ocv=str(ocv), ieee80211w="1", disable_ht="1")
        dev[1].connect(ssid, psk=passphrase, scan_freq="2437", ocv=str(ocv), ieee80211w="1")

@remote_compatible
def test_wpa2_ocv_ht40(dev, apdev):
    for channel, capab, freq, mode in [( "6", "[HT40-]", "2437", "g"),
                                       ( "6", "[HT40+]", "2437", "g"),
                                       ("40", "[HT40-]", "5200", "a"),
                                       ("36", "[HT40+]", "5180", "a")]:
        params = { "hw_mode": mode, "channel": channel, "country_code": "US",  "ieee80211n": "1",
                   "ht_capab": capab,  "ieee80211w": "1", "ocv": "1"}
        hapd, ssid, passphrase = ocv_setup_ap(apdev[0], params)
        for ocv in range(2):
            dev[0].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1", disable_ht="1")
            dev[1].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1")
        reset_ap(apdev[0])

@remote_compatible
def test_wpa2_ocv_vht40(dev, apdev):
    for channel, capab, freq in [("40", "[HT40-]", "5200"),
                                 ("36", "[HT40+]", "5180")]:
        params = { "hw_mode": "a", "channel": channel, "country_code": "US",
                   "ht_capab": capab, "ieee80211n": "1", "ieee80211ac": "1",
                   "vht_oper_chwidth": "0", "vht_oper_centr_freq_seg0_idx": "38",
                   "ieee80211w": "1", "ocv": "1"}
        hapd, ssid, passphrase = ocv_setup_ap(apdev[0], params)
        for ocv in range(2):
            dev[0].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1", disable_ht="1")
            dev[1].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1", disable_vht="1")
            dev[2].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1")
        reset_ap(apdev[0])

@remote_compatible
def test_wpa2_ocv_vht80(dev, apdev):
    for channel, capab, freq in [("40", "[HT40-]", "5200"),
                                 ("36", "[HT40+]", "5180")]:
        params = { "hw_mode": "a", "channel": channel, "country_code": "US",
                   "ht_capab": capab, "ieee80211n": "1", "ieee80211ac": "1",
                   "vht_oper_chwidth": "1", "vht_oper_centr_freq_seg0_idx": "42",
                   "ieee80211w": "1", "ocv": "1"}
        hapd, ssid, passphrase = ocv_setup_ap(apdev[0], params)
        for ocv in range(2):
            dev[0].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1", disable_ht="1")
            dev[1].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1", disable_vht="1")
            dev[2].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1")
        reset_ap(apdev[0])

@remote_compatible
def test_wpa2_ocv_vht160(dev, apdev):
    for channel, capab, freq in [("100", "[HT40+]", "5500"),
                                 ("104", "[HT40-]", "5520")]:
        params = { "hw_mode": "a", "channel": channel, "country_code": "ZA",
                   "ht_capab": capab, "ieee80211n": "1", "ieee80211ac": "1",
                   "vht_oper_chwidth": "2", "vht_oper_centr_freq_seg0_idx": "114",
                   "ieee80211w": "1", "ocv": "1"}
        hapd, ssid, passphrase = ocv_setup_ap(apdev[0], params)
        for ocv in range(2):
            dev[0].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1", disable_ht="1")
            dev[1].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1", disable_vht="1")
            dev[2].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1")
        reset_ap(apdev[0])

@remote_compatible
def test_wpa2_ocv_vht80plus80(dev, apdev):
    for channel, capab, freq in [("36", "[HT40+]", "5180"),
                                 ("40", "[HT40-]", "5200")]:
        params = { "hw_mode": "a", "channel": channel, "country_code": "US",
                   "ht_capab": capab, "ieee80211n": "1", "ieee80211ac": "1",
                   "vht_oper_chwidth": "3", "vht_oper_centr_freq_seg0_idx": "42",
                   "vht_oper_centr_freq_seg1_idx": "155", "ieee80211w": "1",
                   "ieee80211d": "1", "ieee80211h": "1", "ocv": "1"}
        hapd, ssid, passphrase = ocv_setup_ap(apdev[0], params)
        for ocv in range(2):
            dev[0].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1", disable_ht="1")
            dev[1].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1", disable_vht="1")
            dev[2].connect(ssid, psk=passphrase, scan_freq=freq, ocv=str(ocv), ieee80211w="1")
        reset_ap(apdev[0])

@remote_compatible
def test_wpa2_ocv_mismatch_ap(dev, apdev):
    params = { "channel": "1", "ieee80211w": "1", "ocv": "1", "freq": "2412"}
    conn = APConnection(apdev[0], dev[0], params)
    conn.test_bad_oci("element missing", None, 0, 0)
    conn.test_bad_oci("wrong channel number", 81, 6, 0)
    conn.test_bad_oci("invalid channel number", 81, 0, 0)
    conn.test_bad_oci("wrong operating class", 80, 0, 0)
    conn.test_bad_oci("invalid operating class", 0, 0, 0)
    conn.confirm_valid_oci(81, 1, 0)

@remote_compatible
def test_wpa2_ocv_ht_mismatch_ap(dev, apdev):
    params = { "channel": "6", "ht_capab": "[HT40-]", "ieee80211w": "1",
               "ocv": "1", "freq": "2437"}
    conn = APConnection(apdev[0], dev[0], params)
    conn.test_bad_oci("wrong primary channel", 84, 5, 0)
    conn.test_bad_oci("lower bandwidth than negotiated", 81, 6, 0)
    conn.test_bad_oci("bad upper/lower channel", 83, 6, 0)
    conn.confirm_valid_oci(84, 6, 0)

@remote_compatible
def test_wpa2_ocv_vht80_mismatch_ap(dev, apdev):
    params = { "hw_mode": "a", "channel": "36", "country_code": "US",
               "ht_capab": "[HT40+]", "ieee80211w": "1", "ieee80211n": "1",
               "ieee80211ac": "1", "vht_oper_chwidth": "1", "ocv": "1",
               "vht_oper_centr_freq_seg0_idx": "42", "freq": "5180" }
    conn = APConnection(apdev[0], dev[0], params)
    conn.test_bad_oci("wrong primary channel", 128, 38, 0)
    conn.test_bad_oci("wrong primary channel", 128, 32, 0)
    conn.test_bad_oci("smaller bandwidth than negotiated", 116, 36, 0)
    conn.test_bad_oci("smaller bandwidth than negotiated", 115, 36, 0)
    conn.confirm_valid_oci(128, 36, 0)

@remote_compatible
def test_wpa2_ocv_vht160_mismatch_ap(dev, apdev):
    params = { "hw_mode": "a", "channel": "100", "country_code": "ZA",
               "ht_capab": "[HT40+]", "ieee80211w": "1", "ieee80211n": "1",
               "ieee80211ac": "1", "vht_oper_chwidth": "2", "ocv": "1",
               "vht_oper_centr_freq_seg0_idx": "114", "freq": "5500",
               "ieee80211d": "1", "ieee80211h": "1" }
    conn = APConnection(apdev[0], dev[0], params)
    conn.test_bad_oci("wrong primary channel", 129, 36, 0)
    conn.test_bad_oci("wrong primary channel", 129, 114, 0)
    conn.test_bad_oci("smaller bandwidth (20 Mhz) than negotiated", 121, 100, 0)
    conn.test_bad_oci("smaller bandwidth (40 Mhz) than negotiated", 122, 100, 0)
    conn.test_bad_oci("smaller bandwidth (80 Mhz) than negotiated", 128, 100, 0)
    conn.test_bad_oci("using 80+80 channel instead of 160", 130, 100, 155)
    conn.confirm_valid_oci(129, 100, 0)

@remote_compatible
def test_wpa2_ocv_vht80plus80_mismatch_ap(dev, apdev):
    params = { "hw_mode": "a", "channel": "36", "country_code": "US",
               "ht_capab": "[HT40+]", "ieee80211w": "1", "ieee80211n": "1",
               "ieee80211ac": "1", "vht_oper_chwidth": "3", "ocv": "1",
               "vht_oper_centr_freq_seg0_idx": "42", "freq": "5180",
               "vht_oper_centr_freq_seg1_idx": "155", "ieee80211d": "1",
               "ieee80211h": "1" }
    conn = APConnection(apdev[0], dev[0], params)
    conn.test_bad_oci("using 80 MHz operating class", 128, 36, 155)
    conn.test_bad_oci("wrong frequency segment 1", 130, 36, 138)
    conn.confirm_valid_oci(130, 36, 155)

@remote_compatible
def test_wpa2_ocv_ap_unexpected1(dev, apdev):
    params = { "channel": "1", "ieee80211w": "1", "ocv": "0",
               "sta_ocv": "1", "freq": "2412" }
    conn = APConnection(apdev[0], dev[0], params)
    logger.debug("Client will send OCI KDE even if it was not negotiated")
    conn.confirm_valid_oci(81, 1, 0)

@remote_compatible
def test_wpa2_ocv_ap_unexpected2(dev, apdev):
    params = { "channel": "1", "ieee80211w": "1", "ocv": "1",
               "sta_ocv": "0", "freq": "2412" }
    conn = APConnection(apdev[0], dev[0], params)
    logger.debug("Client will send OCI KDE even if it was not negotiated")
    conn.confirm_valid_oci(81, 1, 0)


class STAConnection:
    def __init__(self):
        self.hapd = None
        self.dev  = None
        self.bssid = None
        self.addr = None
        self.rsne = None
        self.gtkie = None
        self.kck  = None
        self.kek  = None
        self.msg  = None
        self.anonce = None
        self.snonce = None

    def __init__(self, apdev, dev, params, sta_params=None):
        self.dev = dev
        self.bssid = apdev['bssid']

        freq = params.pop("freq")
        if sta_params is None:
            sta_params = dict()
        if not "ocv" in sta_params:
            sta_params["ocv"] = "1"
        if not "ieee80211w" in sta_params:
            sta_params["ieee80211w"] = "1"

        ssid = "test-wpa2-ocv"
        passphrase = "qwertyuiop"
        psk = "c2c6c255af836bed1b3f2f1ded98e052f5ad618bb554e2836757b55854a0eab7"
        params.update(hostapd.wpa2_params(ssid=ssid, passphrase=passphrase))
        params['wpa_pairwise_update_count'] = "10"

        self.hapd = hostapd.add_ap(apdev, params)
        self.hapd.request("SET ext_eapol_frame_io 1")
        self.dev.request("SET ext_eapol_frame_io 1")
        pmk = binascii.unhexlify("c2c6c255af836bed1b3f2f1ded98e052f5ad618bb554e2836757b55854a0eab7")

        self.gtkie = binascii.unhexlify("dd16000fac010100dc11188831bf4aa4a8678d2b41498618")
        if sta_params["ocv"] != "0":
            # FIXME: Can we avoid hostapd from adding the last element????
            self.rsne = binascii.unhexlify("30140100000fac040100000fac040100000fac028c40")
            #self.rsne = binascii.unhexlify("301a0100000fac040100000fac040100000fac0280400000000fac06")
        else:
            self.rsne = binascii.unhexlify("30140100000fac040100000fac040100000fac028c00")
            #self.rsne = binascii.unhexlify("301a0100000fac040100000fac040100000fac0280000000000fac06")

        self.dev.connect(ssid, raw_psk=psk, scan_freq=freq, wait_connect=False, **sta_params)
        self.addr = dev.p2p_interface_addr()

        # Forward msg 1/4 from AP to STA
        self.msg = recv_eapol(self.hapd)
        self.anonce = self.msg['rsn_key_nonce']
        send_eapol(self.dev, self.bssid, build_eapol(self.msg))

        # Capture msg 2/4 from the STA so we can derive the session keys
        self.msg = recv_eapol(dev)
        self.snonce = self.msg['rsn_key_nonce']
        (ptk, self.kck, self.kek) = pmk_to_ptk(pmk, self.addr, self.bssid, self.snonce,self.anonce)

        self.counter = struct.unpack('>Q', self.msg['rsn_replay_counter'])[0] + 1


    def test_bad_oci(self, logmsg, op_class, channel, seg1_idx, errmsg):
        # FIXME: Only print errmsg?
        logger.info("Bad OCI element: " + logmsg)
        if op_class is None:
            ocikde = ""
        else:
            ocikde = make_ocikde(op_class, channel, seg1_idx)

        plain = self.rsne + self.gtkie + ocikde
        wrapped = aes_wrap(self.kek, pad_key_data(plain))
        msg = build_eapol_key_3_4(self.anonce, self.kck, wrapped, replay_counter=self.counter)

        self.dev.dump_monitor()
        send_eapol(self.dev, self.bssid, build_eapol(msg))
        self.counter += 1

        ev = self.dev.wait_event([errmsg], timeout=5)
        if ev is None:
            raise Exception("Bad OCI not reported")


    def confirm_valid_oci(self, op_class, channel, seg1_idx):
        logger.debug("Valid OCI element to complete handshake")
        ocikde = make_ocikde(op_class, channel, seg1_idx)

        plain = self.rsne + self.gtkie + ocikde
        wrapped = aes_wrap(self.kek, pad_key_data(plain))
        msg = build_eapol_key_3_4(self.anonce, self.kck, wrapped, replay_counter=self.counter)

        self.dev.dump_monitor()
        send_eapol(self.dev, self.bssid, build_eapol(msg))
        self.counter += 1

        self.dev.wait_connected(timeout=1)

@remote_compatible
def test_wpa2_ocv_mismatch_client(dev, apdev):
    params = { "channel": "1", "ieee80211w": "1", "ocv": "1", "freq": "2412"}
    conn = STAConnection(apdev[0], dev[0], params)
    conn.test_bad_oci("element missing", None, 0, 0, "AP did not include OCI")
    conn.test_bad_oci("wrong channel number", 81, 6, 0, "Primary channel mismatch")
    conn.test_bad_oci("invalid channel number", 81, 0, 0, "Unable to interpret the OCI")
    conn.test_bad_oci("wrong operating class", 80, 0, 0, "Unable to interpret the OCI")
    conn.test_bad_oci("invalid operating class", 0, 0, 0, "Unable to interpret the OCI")
    conn.confirm_valid_oci(81, 1, 0)

@remote_compatible
def test_wpa2_ocv_vht160_mismatch_client(dev, apdev):
    params = { "hw_mode": "a", "channel": "100", "country_code": "ZA",
               "ht_capab": "[HT40+]", "ieee80211w": "1", "ieee80211n": "1",
               "ieee80211ac": "1", "vht_oper_chwidth": "2", "ocv": "1",
               "vht_oper_centr_freq_seg0_idx": "114", "freq": "5500",
               "ieee80211d": "1", "ieee80211h": "1" }
    sta_params = { "disable_vht": "1" }
    conn = STAConnection(apdev[0], dev[0], params, sta_params)
    conn.test_bad_oci("smaller bandwidth (20 Mhz) than negotiated", 121, 100, 0, "Channel bandwidth mismatch")
    conn.test_bad_oci("wrong frequency, bandwith, and secondary channel", 123, 104, 0, "Primary channel mismatch")
    conn.test_bad_oci("wrong upper/lower behaviour", 129, 104, 0, "Primary channel mismatch")
    #conn.test_bad_oci("smaller bandwidth (40 Mhz) than negotiated", 122, 100, 0, "Channel bandwidth mismatch")

    conn.confirm_valid_oci(122, 100, 0)
    #conn.confirm_valid_oci(129, 100, 0)

# ex:set ts=4 et:
