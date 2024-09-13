from scapy.all import ARP, Ether, srp
from tqdm import tqdm
import ipaddress
import concurrent.futures

def scan_ip(ip):
    # Создаем ARP-запрос для одной IP
    arp = ARP(pdst=str(ip))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Отправляем пакет и получаем ответ
    result = srp(packet, timeout=1, verbose=0)[0]

    # Собираем найденные устройства
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def scan_network(network):
    # Указываем диапазон IP-адресов для сканирования
    ip_range = ipaddress.ip_network(network, strict=False)
    devices = []

    # Создаем пул потоков
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        # Используем tqdm для отображения прогресс-бара
        futures = [executor.submit(scan_ip, ip) for ip in ip_range]
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Scanning Network", unit="IP"):
            devices.extend(future.result())

    return devices

def print_devices(devices):
    print("IP Address\tMAC Address")
    print("-------------------------")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")

if __name__ == "__main__":
    # Указываем диапазон IP-адресов в локальной сети
    network = "192.168.1.0/24"  # Замените на вашу сеть
    devices = scan_network(network)
    print_devices(devices)
