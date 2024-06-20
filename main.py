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

def hop_channels(interface, channels, delay):
    global current_channel
    while True:
        for channel in channels:
            current_channel = channel
            system(f"iwconfig {interface} channel {channel}")
            sleep(delay)

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--interface", "interface", "Network Interface to Start Sniffing on"),
                              ('-c', "--channel", "channel", "Channels to Sniff on (Seperated by ',' if multiple, Default=Channel Hopping)"),
                              ('-d', "--delay", "delay", f"Delay Between Channel Hopping (Default={channel_hopping_delay})")
                              ('-w', "--write", "write", "Dump Packets to a File"))
    if not check_root():
        display('-', f"This Program requires {Back.YELLOW}root{Back.RESET} Privileges")
        exit(0)
    if not arguments.interface:
        display('-', "Please specify an Interface")
        display('*', f"Available Interfaces : {Back.MAGENTA}{get_if_list()}{Back.RESET}")
        exit(0)
    if not arguments.channel:
        arguments.channel = [channel for channel in range(1, 15)]
    else:
        arguments.channel = arguments.channel.split(',')
    if not arguments.delay:
        arguments.delay = channel_hopping_delay
    else:
        arguments.delay = float(arguments.delay)
    display(':', f"Starting Channel Hopping Daemon Thread on Channels {Back.MAGENTA}{','.join(arguments.channels)}{Back.RESET}")
    Thread(target=hop_channels, args=(arguments.interface, arguments.channel, arguments.delay), daemon=True)