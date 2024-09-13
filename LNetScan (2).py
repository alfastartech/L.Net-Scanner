from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
from tqdm import tqdm
import ipaddress
import concurrent.futures
import socket

def scan_ip(ip):
    # Создаем ARP-запрос для одной IP
    arp = ARP(pdst=str(ip))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Отправляем пакет и получаем ответ
    result = srp(packet, timeout=1, verbose=0)[0]
    
    devices = []
    for sent, received in result:
        # Измерение задержки (пинг)
        delay = measure_ping(str(received.psrc))
        
        # Проверка наличия HTTP и HTTPS сервера
        has_http = check_http_server(str(received.psrc))
        
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'delay': delay,
            'has_http': has_http
        })
    
    return devices

def measure_ping(ip):
    try:
        # Создаем ICMP-запрос
        packet = IP(dst=ip)/ICMP()
        reply = sr1(packet, timeout=1, verbose=0)
        
        if reply:
            return reply.time - packet.sent_time
        else:
            return None
    except Exception as e:
        return None

def check_http_server(ip):
    for port in [80, 443]:  # Проверяем HTTP и HTTPS
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect((ip, port))
                return True
            except (socket.timeout, socket.error):
                continue
    return False

def scan_network(network):
    # Указываем диапазон IP-адресов для сканирования
    ip_range = ipaddress.ip_network(network, strict=False)
    devices = []

    # Создаем пул потоков
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
        # Используем tqdm для отображения прогресс-бара
        futures = [executor.submit(scan_ip, ip) for ip in ip_range]
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Scanning Network", unit="IP"):
            devices.extend(future.result())

    return devices

def print_devices(devices):
    print("IP Address\tMAC Address\tDelay (s)\tHTTP")
    print("-----------------------------------------------")
    for device in devices:
        delay = device['delay']
        delay_str = f"{delay:.2f}" if delay is not None else "N/A"
        has_http = "Yes" if device['has_http'] else "No"
        print(f"{device['ip']}\t{device['mac']}\t{delay_str}\t{has_http}")

if __name__ == "__main__":
    # Указываем диапазон IP-адресов в локальной сети
    network = "192.168.1.0/24"  # Замените на вашу сеть
    devices = scan_network(network)
    print_devices(devices)
