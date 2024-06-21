#! /usr/bin/env python3

from os import geteuid, system
from scapy.all import *
from datetime import date
from optparse import OptionParser
from colorama import Fore, Back, Style
from threading import Thread, Lock
from time import strftime, localtime, sleep, time

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

def check_root():
    return geteuid() == 0

lock = Lock()
current_channel = None
channel_hopping_delay = 0.5
TABLINE = '\t'
running = True

beacon_frames = {}
access_points = {}
probes = {}

def hop_channels(interface, channels, delay):
    global current_channel
    while running:
        for channel in channels:
            with lock:
                current_channel = channel
            system(f"iwconfig {interface} channel {channel}")
            sleep(delay)
def process_packet(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2.upper()
        essid = packet[Dot11Elt].info.decode()
        rate = packet[RadioTap].Rate
        channel_frequency = packet[RadioTap].ChannelFrequency
        signal_strength = packet[RadioTap].dBm_AntSignal
        network_stats = packet[Dot11Beacon].network_stats()
        channel = network_stats["channel"]
        crypto = list(network_stats["crypto"])[0]
        with lock:
            access_points[bssid] = {
                "essid" : essid,
                "rate" : rate,
                "channel_frequency" : channel_frequency,
                "signal_strength" : signal_strength,
                "channel" : channel,
                "crypto" : crypto,
            }
            if bssid not in beacon_frames.keys():
                beacon_frames[bssid] = 0
            beacon_frames[bssid] += 1
    if packet.haslayer(Dot11ProbeReq):
        bssid = packet[Dot11].addr2.upper()
        probe_essid = packet[Dot11Elt].info.decode()
        rate = packet[RadioTap].Rate
        channel_frequency = packet[RadioTap].ChannelFrequency
        signal_strength = packet[RadioTap].dBm_AntSignal
        with lock:
            if bssid not in probes.keys():
                probes[bssid] = {"probes": set()}
            probes[bssid]["rate"] = rate
            probes[bssid]["channel_frequency"] = channel_frequency
            probes[bssid]["signal_strength"] = signal_strength
            probes[bssid]["probes"].add(probe_essid)
def display_details():
    while running:
        system("clear")
        with lock:
            print(f"Current Channel = {current_channel}\n{Fore.CYAN}BSSID            \tPOWER\tBEACONS\tCHANNEL\tRATE\tFREQUENCY\tCRYPTO\t\tESSID{Fore.RESET}")
            for bssid, info in access_points.items():
                print(f"{Fore.GREEN}{bssid}\t{info['signal_strength']}\t{beacon_frames[bssid]}\t{info['channel']}\t{info['rate']}\t{info['channel_frequency']}MHz  \t{info['crypto']}\t{TABLINE if len(info['crypto']) < 10 else ''}{info['essid']}{Fore.RESET}")
        sleep(1)

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--interface", "interface", "Network Interface to Start Sniffing on"),
                              ('-c', "--channel", "channel", "Channels to Sniff on (Seperated by ',' if multiple, Default=Channel Hopping)"),
                              ('-d', "--delay", "delay", f"Delay Between Channel Hopping (Default={channel_hopping_delay})"),
                              ('-w', "--write", "write", "Dump Packets to a File"))
    if not check_root():
        display('-', f"This Program requires {Back.YELLOW}root{Back.RESET} Privileges")
        exit(0)
    if not arguments.interface or arguments.interface not in get_if_list():
        display('-', "Please specify a Valid Interface")
        display('*', f"Available Interfaces : {Back.MAGENTA}{','.join(get_if_list())}{Back.RESET}")
        exit(0)
    if not arguments.channel:
        arguments.channel = [str(channel) for channel in range(1, 15)]
    else:
        arguments.channel = arguments.channel.split(',')
    if not arguments.delay:
        arguments.delay = channel_hopping_delay
    else:
        arguments.delay = float(arguments.delay)
    display(':', f"Starting Channel Hopping Daemon Thread on Channels {Back.MAGENTA}{','.join(arguments.channel)}{Back.RESET}")
    Thread(target=hop_channels, args=(arguments.interface, arguments.channel, arguments.delay), daemon=True).start()
    display(':', f"Starting Sniffing on Interface {Back.MAGENTA}{arguments.interface}{Back.RESET}")
    sleep(1)
    Thread(target=display_details, daemon=True).start()
    try:
        packets = sniff(iface=arguments.interface, prn=process_packet)
    except KeyboardInterrupt:
        display('*', f"Keyboard Interrupt Detected! Exiting...", start='\n')
    except Exception as error:
        display('-', f"Error Occured = {Back.YELLOW}{error}{Back.RESET}")
    display('*', "Exiting")
    running = False
    sleep(arguments.delay + 2)
    if arguments.write:
        display('+', f"Dumping Packets to file {Back.MAGENTA}{arguments.write}{Back.RESET}")
        wrpcap(arguments.write, packets)