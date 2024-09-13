from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
from tqdm import tqdm
import ipaddress
import concurrent.futures
import socket
from flask import Flask, render_template_string

app = Flask(__name__)

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
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        # Используем tqdm для отображения прогресс-бара
        futures = [executor.submit(scan_ip, ip) for ip in ip_range]
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Scanning Network", unit="IP"):
            devices.extend(future.result())

    return devices

@app.route('/')
def index():
    network = "192.168.1.0/24"  # Замените на вашу сеть
    devices = scan_network(network)

    # Генерация HTML-страницы с таблицей
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Network Scan Results</title>
        <style>
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid black; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            a { color: blue; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .disabled { color: grey; cursor: not-allowed; }
        </style>
    </head>
    <body>
        <h1>Network Scan Results</h1>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Delay (s)</th>
                    <th>HTTP</th>
                </tr>
            </thead>
            <tbody>
    """
    for device in devices:
        delay = device['delay']
        delay_str = f"{delay:.2f}" if delay is not None else "N/A"
        has_http = "Yes" if device['has_http'] else "No"
        ip_display = device['ip']
        
        if device['has_http']:
            ip_link = f"http://{device['ip']}"
            html += f"""
                <tr>
                    <td><a href="{ip_link}" target="_blank">{ip_display}</a></td>
                    <td>{device['mac']}</td>
                    <td>{delay_str}</td>
                    <td>{has_http}</td>
                </tr>
            """
        else:
            html += f"""
                <tr>
                    <td class="disabled">{ip_display}</td>
                    <td>{device['mac']}</td>
                    <td>{delay_str}</td>
                    <td>{has_http}</td>
                </tr>
            """
    
    html += """
            </tbody>
        </table>
    </body>
    </html>
    """
    return render_template_string(html)

if __name__ == "__main__":
    app.run(debug=False)
