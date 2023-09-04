"""
Wireless Probe Requests

Wireless Probe Requests are an essential part of Wi-Fi communication. They play a crucial role in the process of discovering and connecting to wireless networks. In this detailed explanation, will be shown what wireless probe requests are, how they work, and their significance in Wi-Fi networks.

by DFT
"""

import colorama
from tabulate import tabulate

import argparse
import signal
from datetime import datetime
from os import system
from sys import exit
from threading import Thread
from time import sleep

from scapy.layers.dot11 import Dot11ProbeReq, Dot11Elt, sniff

# globals
LOG_FILE = "LOG_myWi02.txt"

probes = []
CHANNEL = 1
INTERFACE = None
SLEEP_CH = 2.5
SLEEP_SAVER = 30

colorama.init()


def keyboard_interrupt_handler(interrupt_signal, frame):
    print("Scanning finished")
    print("KeyboardInterrupt ID: {} {} has been caught.".format(interrupt_signal, frame))
    exit(1)


def packet_sta(packet):
    global probes
    try:
        if packet.haslayer(Dot11ProbeReq) and packet.haslayer(Dot11Elt):
            dthr = str(datetime.now())
            if packet.type == 0 and packet.subtype == 4:
                mac = str(packet.addr2).upper()
                ssid = packet[Dot11Elt].info.decode().strip()

                if not ssid:
                    ssid = "N/A"
                if hasattr(packet, "dBm_AntSignal"):
                    dbm = packet.dBm_AntSignal
                else:
                    dbm = "?"

                existing_item = next((item for item in probes if item["STA"] == mac), None)

                if existing_item:
                    # Updating known item
                    existing_item["last_seen"] = str(datetime.now())
                    existing_item["dBm_AntSignal"] = dbm
                    existing_item["spoted"] = existing_item["spoted"] + 1
                    if existing_item["SSID"] == "N/A":
                        existing_item["SSID"] = ssid
                    elif existing_item["SSID"] != ssid:
                        existing_item["SSID"] = " * " + ssid

                if all(item["STA"] != mac for item in probes):
                    # Append unknown item
                    probe = {"STA": mac, "SSID": ssid, "last_seen": dthr, "spoted": 1, "dBm_AntSignal": dbm}
                    probes.append(probe)

                print("\033[2J")
                print("CHANNEL", CHANNEL)

                probes = sorted(probes, key=lambda p: p["dBm_AntSignal"], reverse=True)

                print(tabulate(probes, headers={"STA": "\033[96mSTATION",
                                                "SSID": "SSID",
                                                "last_seen": "LAST SEEN",
                                                "spoted": "TIMES SPOTED",
                                                "dBm_AntSignal": "dBm_AntSignal\033[0m"}))
    except Exception as e:
        print("Exception packet_sta()", e)


def change_channel():
    global INTERFACE, CHANNEL, SLEEP_CH
    try:
        while True:
            system(f"iwconfig {INTERFACE} channel {CHANNEL}")
            CHANNEL = CHANNEL % 14 + 1
            sleep(SLEEP_CH)
    except Exception as e:
        print("Exception change_channel()", e)


def auto_save():
    global SLEEP_SAVER, LOG_FILE, probes
    try:
        print("Auto saving data...")
        while True:
            sleep(SLEEP_SAVER)

            with open(LOG_FILE, "a") as fp:

                fp.write("-"*80 + "\n" + str(datetime.now()) + "\n")

                for probe in probes:
                    fp.write(str(probe) + "\n")

            print("Data saved in ", LOG_FILE)

    except Exception as e:
        print("Exception auto_save()", e)


def run_app():
    global INTERFACE

    try:
        print("\033[2J")
        description = "\tSimple wireless probe request scanner using scapy. This type of packet is fundamental to the operation of Wi-Fi networks, allowing devices to discover and connect to available networks efficiently. They are a crucial part of the initial handshake between client devices and access points."
        epilog = "by DFT"
        parser = argparse.ArgumentParser(description=description, epilog=epilog)
        parser.add_argument("interface", help='Enter the mode monitor activated wireless interface. Ex.: wlan0')
        args = parser.parse_args()

        if len(args.interface) < 1:
            print("Provide the interface to be used. Try again!")
            exit(1)
        else:
            INTERFACE = args.interface

        channel_ch_thread = Thread(target=change_channel)
        channel_ch_thread.daemon = True
        channel_ch_thread.start()

        auto_save_thread = Thread(target=auto_save)
        auto_save_thread.daemon = True
        auto_save_thread.start()

        print("-" * 255)

        try:
            sniff(prn=packet_sta, iface=INTERFACE)

        except Exception as er:
            print("Exception on run_app() / sniff", er)

    except Exception as e:
        print("Exception on run_app()", e)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, keyboard_interrupt_handler)
    run_app()
