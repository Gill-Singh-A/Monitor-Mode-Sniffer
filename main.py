#! /usr/bin/env python3

from os import geteuid, system
from scapy.all import *
from pathlib import Path
from datetime import date
from optparse import OptionParser
from colorama import Fore, Back, Style
from threading import Thread, Lock
from time import strftime, localtime, sleep

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

cwd = Path.cwd()
lock = Lock()
current_channel = None
channel_hopping_delay = 0.5
TABLINE = '\t'
running = True

sent_frames, received_frames = {}, {}
beacon_frames = {}
access_points = {}
probes = {}
associations = {}
total_devices = set()
hidden_networks = {}

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
        try:
            recv_addr = packet[Dot11].addr1.upper()
        except:
            recv_addr = "FF:FF:FF:FF:FF:FF"
        essid = packet[Dot11Elt].info.decode()
        rate = packet[RadioTap].Rate
        channel_frequency = packet[RadioTap].ChannelFrequency
        signal_strength = packet[RadioTap].dBm_AntSignal
        network_stats = packet[Dot11Beacon].network_stats()
        channel = network_stats["channel"]
        crypto = list(network_stats["crypto"])[0]
        with lock:
            if bssid not in sent_frames.keys():
                sent_frames[bssid] = 0
            if bssid not in received_frames.keys():
                received_frames[bssid] = 0
            sent_frames[bssid] += 1
            if recv_addr not in received_frames.keys():
                received_frames[recv_addr] = 0
            if recv_addr not in sent_frames.keys():
                sent_frames[recv_addr] = 0
            received_frames[recv_addr] += 1
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
            associations[bssid] = recv_addr
            associations[recv_addr] = bssid
            total_devices.add(bssid)
            total_devices.add(recv_addr)
    elif packet.haslayer(Dot11ProbeReq):
        bssid = packet[Dot11].addr2.upper()
        try:
            recv_addr = packet[Dot11].addr1.upper()
        except:
            recv_addr = "FF:FF:FF:FF:FF:FF"
        probe_essid = packet[Dot11Elt].info.decode()
        rate = packet[RadioTap].Rate
        channel_frequency = packet[RadioTap].ChannelFrequency
        signal_strength = packet[RadioTap].dBm_AntSignal
        with lock:
            if bssid not in sent_frames.keys():
                sent_frames[bssid] = 0
            if bssid not in received_frames.keys():
                received_frames[bssid] = 0
            sent_frames[bssid] += 1
            if recv_addr not in received_frames.keys():
                received_frames[recv_addr] = 0
            if recv_addr not in sent_frames.keys():
                sent_frames[recv_addr] = 0
            received_frames[recv_addr] += 1
            if bssid not in probes.keys():
                probes[bssid] = {"probes": set()}
            probes[bssid]["rate"] = rate
            probes[bssid]["channel_frequency"] = channel_frequency
            probes[bssid]["signal_strength"] = signal_strength
            probes[bssid]["probes"].add(probe_essid)
            associations[bssid] = recv_addr
            associations[recv_addr] = bssid
            total_devices.add(bssid)
            total_devices.add(recv_addr)
    elif packet.haslayer(Dot11ProbeResp):
        try:
            bssid = packet[Dot11].addr2.upper()
        except:
            bssid = "FF:FF:FF:FF:FF:FF"
        try:
            recv_addr = packet[Dot11].addr1.upper()
        except:
            recv_addr = "FF:FF:FF:FF:FF:FF"
        probe_essid = packet[Dot11Elt].info.decode()
        rate = packet[RadioTap].Rate
        channel_frequency = packet[RadioTap].ChannelFrequency
        signal_strength = packet[RadioTap].dBm_AntSignal
        with lock:
            if bssid not in beacon_frames.keys() or access_points.items():
                hidden_networks[bssid] = {
                    "essid" : probe_essid,
                    "rate" : rate,
                    "channel_frequency": channel_frequency,
                    "signal_strength" : signal_strength
                }
            if bssid not in sent_frames.keys():
                sent_frames[bssid] = 0
            if bssid not in received_frames.keys():
                received_frames[bssid] = 0
            sent_frames[bssid] += 1
            if recv_addr not in received_frames.keys():
                received_frames[recv_addr] = 0
            if recv_addr not in sent_frames.keys():
                sent_frames[recv_addr] = 0
            received_frames[recv_addr] += 1
            associations[bssid] = recv_addr
            associations[recv_addr] = bssid
            total_devices.add(bssid)
            total_devices.add(recv_addr)
    elif packet.haslayer(Dot11):
        try:
            bssid = packet[Dot11].addr2.upper()
        except:
            bssid = "FF:FF:FF:FF:FF:FF"
        try:
            recv_addr = packet[Dot11].addr1.upper()
        except:
            recv_addr = "FF:FF:FF:FF:FF:FF"
        with lock:
            if bssid not in sent_frames.keys():
                sent_frames[bssid] = 0
            if bssid not in received_frames.keys():
                received_frames[bssid] = 0
            sent_frames[bssid] += 1
            if recv_addr not in received_frames.keys():
                received_frames[recv_addr] = 0
            if recv_addr not in sent_frames.keys():
                sent_frames[recv_addr] = 0
            received_frames[recv_addr] += 1
            associations[bssid] = recv_addr
            associations[recv_addr] = bssid
            total_devices.add(bssid)
            total_devices.add(recv_addr)
def display_details():
    while running:
        system("clear")
        with lock:
            print(f"Current Channel = {current_channel}\n{Fore.CYAN}BSSID            \tPOWER\tBEACONS\tSENT\tRECV\tCHANNEL\tRATE\tFREQUENCY\tCRYPTO\t\tESSID{Fore.RESET}")
            for bssid, info in access_points.items():
                print(f"{Fore.GREEN}{bssid}\t{info['signal_strength']}\t{beacon_frames[bssid]}\t{sent_frames[bssid]}\t{received_frames[bssid]}\t{info['channel']}\t{info['rate']}\t{info['channel_frequency']}MHz  \t{info['crypto']}\t{TABLINE if len(info['crypto']) < 8 else ''}{info['essid']}{Fore.RESET}")
            print(f"{Fore.CYAN}ASSOCIATED \t\tBSSID            \tPOWER\tRATE\tSENT\tRECV\tFREQUENCY\tPROBES{Fore.RESET}")
            for bssid, info in probes.items():
                print(f"{Fore.GREEN}{'--:--:--:--:--:--' if bssid not in associations or associations[bssid] == 'FF:FF:FF:FF:FF:FF' else associations[bssid]}\t{bssid}\t{info['signal_strength']}\t{info['rate']}\t{sent_frames[bssid]}\t{received_frames[bssid]}\t{info['channel_frequency']}MHz  \t{','.join(info['probes'])}{Fore.RESET}")
            for bssid in beacon_frames.keys():
                if bssid in hidden_networks.keys():
                    hidden_networks.pop(bssid)
            for bssid in access_points.keys():
                if bssid in hidden_networks.keys():
                    hidden_networks.pop(bssid)
            if len(hidden_networks) > 0:
                print(f"{Fore.CYAN}HIDDEN BSSID     \tPOWER\tSENT\tRECV\tRATE\tFREQUENCY\t\tESSID{Fore.RESET}")
                for bssid, info in hidden_networks.items():
                    print(f"{Fore.GREEN}{bssid}\t{info['signal_strength']}\t{sent_frames[bssid]}\t{received_frames[bssid]}\t{info['rate']}\t{info['channel_frequency']}MHz  \t\t{info['essid']}{Fore.RESET}")
            print(f"{Fore.CYAN}Total Devices Discovered{Fore.RESET} => {Fore.GREEN}{len(total_devices)}{Fore.RESET}")
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
        if arguments.write:
            packets = sniff(iface=arguments.interface, prn=process_packet)
        else:
            sniff(iface=arguments.interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        display('*', f"Keyboard Interrupt Detected! Exiting...", start='\n')
    except Exception as error:
        display('-', f"Error Occured = {Back.YELLOW}{error}{Back.RESET}")
    display('*', "Exiting")
    running = False
    sleep(arguments.delay + 2)
    if arguments.write:
        output_directory = cwd / arguments.write
        output_directory.mkdir(exist_ok=True)
        display('+', f"Dumping Data to Directory {Back.MAGENTA}{arguments.write}/{Back.RESET}")
        wrpcap(f"{arguments.write}/packets.pcap", packets)
        with open(f"{arguments.write}/access_points.csv", 'w') as file:
            file.write(f"BSSID,POWER,BEACONS,SENT,RECV,CHANNEL,RATE,FREQUENCY,CRYPTO,ESSID\n")
            file.write('\n'.join([f"{bssid},{info['signal_strength']},{beacon_frames[bssid]},{sent_frames[bssid]},{received_frames[bssid]},{info['channel']},{info['rate']},{info['channel_frequency']}MHz,{info['crypto']},{info['essid']}" for bssid, info in access_points.items()]))
        with open(f"{arguments.write}/probe_requests.csv", 'w') as file:
            file.write(f"ASSOCIATED,BSSID,POWER,RATE,SENT,RECV,FREQUENCY,PROBES\n")
            file.write('\n'.join([f"{'--:--:--:--:--:--' if bssid not in associations or associations[bssid] == 'FF:FF:FF:FF:FF:FF' else associations[bssid]},{bssid},{info['signal_strength']},{info['rate']},{sent_frames[bssid]},{received_frames[bssid]},{info['channel_frequency']}MHz,{','.join(info['probes'])}" for bssid, info in probes.items()]))
        for bssid in beacon_frames.keys():
            if bssid in hidden_networks.keys():
                hidden_networks.pop(bssid)
        for bssid in access_points.keys():
            if bssid in hidden_networks.keys():
                hidden_networks.pop(bssid)
        if len(hidden_networks) > 0:
            with open(f"{arguments.write}/hidden_ssids.csv", 'w') as file:
                file.write("HIDDEN BSSID,POWER,SENT,RECV,RATE,FREQUENCY,ESSID\n")
                file.write('\n'.join([f"{bssid},{info['signal_strength']},{sent_frames[bssid]},{received_frames[bssid]},{info['rate']},{info['channel_frequency']}MHz,{info['essid']}" for bssid, info in hidden_networks.items()]))
        with open(f"{arguments.write}/device_macs.txt", 'w') as file:
            file.write('\n'.join(total_devices))