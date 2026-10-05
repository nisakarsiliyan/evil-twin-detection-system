import json
import csv
import subprocess
import re
import os
import glob
from datetime import datetime


APP_NAME = "EVIL TWIN TESPİT SİSTEMİ"
APP_VERSION = "v1.2"


sample_networks = [
    {"ssid": "CoffeeShopWiFi", "bssid": "AA:BB:CC:11:22:33", "rssi": -45, "channel": 6, "security": "WPA2"},
    {"ssid": "CoffeeShopWiFi", "bssid": "ZZ:YY:XX:99:88:77", "rssi": -20, "channel": 11, "security": "OPEN"},
    {"ssid": "UniversityWiFi", "bssid": "44:55:66:77:88:99", "rssi": -70, "channel": 9, "security": "WPA2"},
    {"ssid": "UniversityWiFi", "bssid": "AA:11:BB:22:CC:33", "rssi": -28, "channel": 3, "security": "OPEN"},
    {"ssid": "HomeNetwork", "bssid": "12:34:56:78:90:AB", "rssi": -60, "channel": 1, "security": "WPA2"},
    {"ssid": "Airport_Free_WiFi", "bssid": "55:66:77:88:99:AA", "rssi": -35, "channel": 6, "security": "OPEN"},
    {"ssid": "LibraryWiFi", "bssid": "88:99:AA:BB:CC:DD", "rssi": -50, "channel": 11, "security": "WPA2"},
    {"ssid": "LibraryWiFi", "bssid": "11:22:33:44:55:66", "rssi": -42, "channel": 11, "security": "WPA2"},
]

last_summary = None


def get_now():
    return datetime.now().strftime("%d.%m.%Y %H:%M:%S")


def get_risk_level(score):
    if score >= 70:
        return "YÜKSEK RİSK"
    if score >= 40:
        return "ORTA RİSK"
    if score > 0:
        return "DÜŞÜK RİSK"
    return "GÜVENLİ"


def calculate_risk(network, reference_network=None):
    risk_score = 0
    reasons = []

    if reference_network is not None:
        if network["bssid"] != reference_network["bssid"]:
            risk_score += 30
            reasons.append("Aynı SSID farklı BSSID ile görüldü")

        if network["channel"] != reference_network["channel"]:
            risk_score += 15
            reasons.append("Referans ağdan farklı kanal kullanıyor")

    if network["security"].upper() == "OPEN":
        risk_score += 40
        reasons.append("Ağ şifrelemesiz/açık")

    if network["rssi"] > -30:
        risk_score += 25
        reasons.append("Sinyal gücü anormal yüksek")

    return min(risk_score, 100), reasons


def create_log_entry(net, risk_score, risk_level, reasons):
    return {
        "time": get_now(),
        "ssid": net["ssid"],
        "bssid": net["bssid"],
        "rssi": net["rssi"],
        "channel": net["channel"],
        "security": net["security"],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
    }


def save_csv(filename, logs):
    fieldnames = [
        "time", "ssid", "bssid", "rssi", "channel",
        "security", "risk_score", "risk_level", "reasons"
    ]

    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for log in logs:
            row = log.copy()
            row["reasons"] = ", ".join(row["reasons"])
            writer.writerow(row)


def save_reports(suspicious_logs, all_logs):
    with open("attack_logs.json", "w", encoding="utf-8") as file:
        json.dump(suspicious_logs, file, indent=4, ensure_ascii=False)

    save_csv("attack_report.csv", suspicious_logs)
    save_csv("all_networks_report.csv", all_logs)


def print_table(logs):
    print("\n================= AĞ TABLOSU =================")
    print(f"{'SSID':25} {'RSSI':>6} {'KANAL':>6} {'RİSK':>15}")
    print("-" * 60)

    for log in logs:
        ssid = log["ssid"][:25]
        print(f"{ssid:25} {log['rssi']:>6} {log['channel']:>6} {log['risk_level']:>15}")

    print("-" * 60)


def print_network_result(net, risk_score, risk_level, reasons):
    print(f"""
SSID: {net['ssid']}
BSSID: {net['bssid']}
RSSI: {net['rssi']}
Kanal: {net['channel']}
Güvenlik: {net['security']}
Risk Skoru: {risk_score}/100
Risk Seviyesi: {risk_level}
Nedenler: {", ".join(reasons) if reasons else "Şüpheli bulgu yok"}
""")


def analyze_networks(networks):
    global last_summary

    ssid_map = {}
    suspicious_logs = []
    all_logs = []

    summary = {
        "total": len(networks),
        "safe": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "suspicious": 0,
    }

    for network in networks:
        ssid = network["ssid"]

        if ssid not in ssid_map:
            ssid_map[ssid] = []

        ssid_map[ssid].append(network)

    print(f"\n=========== {APP_NAME} {APP_VERSION} ===========")
    print(f"Analiz Başlangıç Zamanı: {get_now()}\n")

    for ssid, same_ssid_networks in ssid_map.items():

        if len(same_ssid_networks) == 1:
            net = same_ssid_networks[0]
            risk_score, reasons = calculate_risk(net)
            risk_level = get_risk_level(risk_score)

            if risk_score >= 40:
                print(f"[DİKKAT] {ssid} tek BSSID ile görüldü ancak riskli özellik taşıyor.")
            else:
                print(f"[GÜVENLİ] {ssid} tek BSSID ile görüldü.")

            log_entry = create_log_entry(net, risk_score, risk_level, reasons)
            all_logs.append(log_entry)

            if risk_score >= 40:
                suspicious_logs.append(log_entry)

            print_network_result(net, risk_score, risk_level, reasons)
            print("-" * 55)

        else:
            print(f"[!] Aynı SSID birden fazla BSSID ile görüldü: {ssid}")
            reference_network = same_ssid_networks[0]

            for net in same_ssid_networks:
                risk_score, reasons = calculate_risk(net, reference_network)
                risk_level = get_risk_level(risk_score)

                log_entry = create_log_entry(net, risk_score, risk_level, reasons)
                all_logs.append(log_entry)

                if risk_score >= 40:
                    suspicious_logs.append(log_entry)

                print_network_result(net, risk_score, risk_level, reasons)

            print("-" * 55)

    for log in all_logs:
        if log["risk_level"] == "GÜVENLİ":
            summary["safe"] += 1
        elif log["risk_level"] == "DÜŞÜK RİSK":
            summary["low"] += 1
        elif log["risk_level"] == "ORTA RİSK":
            summary["medium"] += 1
            summary["suspicious"] += 1
        elif log["risk_level"] == "YÜKSEK RİSK":
            summary["high"] += 1
            summary["suspicious"] += 1

    save_reports(suspicious_logs, all_logs)
    last_summary = summary

    print_table(all_logs)

    print("\n=============== SİSTEM ÖZETİ ===============")
    print(f"Analiz Tarihi           : {get_now()}")
    print(f"Toplam Taranan Ağ Sayısı : {summary['total']}")
    print(f"Güvenli Ağ Sayısı        : {summary['safe']}")
    print(f"Düşük Riskli Ağ Sayısı   : {summary['low']}")
    print(f"Orta Riskli Ağ Sayısı    : {summary['medium']}")
    print(f"Yüksek Riskli Ağ Sayısı  : {summary['high']}")
    print(f"Şüpheli Ağ Sayısı        : {summary['suspicious']}")

    print("\nAnaliz başarılı şekilde tamamlandı.")
    print("Şüpheli ağlar attack_report.csv dosyasına kaydedildi.")
    print("Tüm ağlar all_networks_report.csv dosyasına kaydedildi.")


def get_live_networks_from_user():
    networks = []

    print("\nKablosuz Ağ Tanıları > Tara ekranındaki canlı ağ bilgilerini gir.")
    print("Bitirmek için SSID kısmına 'bitti' yaz.\n")

    while True:
        ssid = input("SSID: ")

        if ssid.lower() == "bitti":
            break

        bssid = input("BSSID: ")

        try:
            rssi = int(input("RSSI: "))
            channel = int(input("Kanal: "))
        except ValueError:
            print("RSSI ve Kanal sadece sayı olmalı. Bu ağ atlandı.")
            continue

        security = input("Güvenlik (WPA2 / WPA3 / OPEN): ")

        networks.append({
            "ssid": ssid,
            "bssid": bssid,
            "rssi": rssi,
            "channel": channel,
            "security": security.upper(),
        })

        print("\nAğ eklendi.\n")

    if len(networks) == 0:
        print("Hiç ağ girilmedi.")
        return

    analyze_networks(networks)


def find_latest_pcap():
    pcap_files = glob.glob("/var/tmp/*.pcap")

    if not pcap_files:
        return None

    return max(pcap_files, key=os.path.getmtime)


def find_all_pcaps():
    return glob.glob("/var/tmp/*.pcap")


def parse_pcap_files(pcap_files):
    networks = {}

    for pcap_file in pcap_files:
        command = ["tcpdump", "-nn", "-e", "-r", pcap_file]

        try:
            result = subprocess.run(command, capture_output=True, text=True)
        except FileNotFoundError:
            print("tcpdump bulunamadı.")
            return []

        for line in result.stdout.splitlines():

            if "Beacon" not in line:
                continue

            ssid_match = re.search(r"Beacon \((.*?)\)", line)
            bssid_match = re.search(r"BSSID:([0-9a-f:]{17})", line)
            rssi_match = re.search(r"(-\d+)dBm signal", line)
            channel_match = re.search(r"CH: (\d+)", line)

            if ssid_match and bssid_match:
                ssid = ssid_match.group(1)
                bssid = bssid_match.group(1)
                rssi = int(rssi_match.group(1)) if rssi_match else -70
                channel = int(channel_match.group(1)) if channel_match else 0
                security = "WPA2" if "PRIVACY" in line else "OPEN"

                key = ssid + "_" + bssid

                networks[key] = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "rssi": rssi,
                    "channel": channel,
                    "security": security,
                }

    return list(networks.values())


def analyze_latest_pcap():
    print("\nPCAP dosyasından otomatik analiz modu")

    latest_pcap = find_latest_pcap()

    if latest_pcap is None:
        print("/var/tmp içinde PCAP dosyası bulunamadı.")
        return

    print(f"Kullanılan PCAP dosyası: {latest_pcap}")

    networks = parse_pcap_files([latest_pcap])

    if len(networks) == 0:
        print("PCAP içinde Beacon paketi bulunamadı.")
        return

    print(f"\nPCAP içinden {len(networks)} ağ çıkarıldı.")
    analyze_networks(networks)


def analyze_all_pcaps():
    print("\nTüm PCAP dosyalarından toplu analiz modu")

    pcap_files = find_all_pcaps()

    if not pcap_files:
        print("/var/tmp içinde PCAP dosyası bulunamadı.")
        return

    print(f"Bulunan PCAP dosyası sayısı: {len(pcap_files)}")

    networks = parse_pcap_files(pcap_files)

    if len(networks) == 0:
        print("PCAP dosyalarında Beacon paketi bulunamadı.")
        return

    print(f"\nPCAP dosyalarından toplam {len(networks)} benzersiz ağ çıkarıldı.")
    analyze_networks(networks)


def show_last_summary():
    if last_summary is None:
        print("\nHenüz analiz yapılmadı.")
        return

    print("\n=============== SON ANALİZ ÖZETİ ===============")
    print(f"Toplam Ağ      : {last_summary['total']}")
    print(f"Güvenli        : {last_summary['safe']}")
    print(f"Düşük Risk     : {last_summary['low']}")
    print(f"Orta Risk      : {last_summary['medium']}")
    print(f"Yüksek Risk    : {last_summary['high']}")
    print(f"Şüpheli Toplam : {last_summary['suspicious']}")


def show_saved_report():
    try:
        with open("attack_logs.json", "r", encoding="utf-8") as file:
            logs = json.load(file)

        if not logs:
            print("\nKayıtlı şüpheli ağ raporu bulunamadı.")
            return

        print("\n=========== KAYITLI ŞÜPHELİ AĞ RAPORU ===========\n")

        for log in logs:
            print(f"""
Zaman: {log['time']}
SSID: {log['ssid']}
BSSID: {log['bssid']}
RSSI: {log['rssi']}
Kanal: {log['channel']}
Güvenlik: {log['security']}
Risk Skoru: {log['risk_score']}/100
Risk Seviyesi: {log['risk_level']}
Nedenler: {", ".join(log['reasons'])}
""")
            print("-" * 55)

    except FileNotFoundError:
        print("\nHenüz rapor dosyası oluşmamış. Önce analiz başlatmalısın.")


def main_menu():
    while True:
        print(f"""
===============================
 {APP_NAME} {APP_VERSION}
===============================
1 - Simülasyon analizi başlat
2 - Gerçek Wi-Fi taraması hakkında bilgi
3 - Canlı ağ verisi gir ve analiz et
4 - En son PCAP dosyasından otomatik analiz et
5 - Tüm PCAP dosyalarını toplu analiz et
6 - Son analiz özetini görüntüle
7 - Kayıtlı şüpheli raporu görüntüle
8 - Çıkış
""")

        choice = input("Seçiminiz: ")

        if choice == "1":
            analyze_networks(sample_networks)

        elif choice == "2":
            print("""
Gerçek Wi-Fi verisi iki yöntemle alınabilir:

1. Kablosuz Ağ Tanıları > Tara ekranı:
   SSID, BSSID, RSSI, kanal ve güvenlik tipi canlı olarak görülebilir.

2. Kablosuz Ağ Tanıları > Dinleyici:
   Belirli kanalda PCAP dosyası oluşturulur.
   Sistem /var/tmp klasöründeki PCAP dosyalarını okuyarak
   Beacon paketlerinden SSID, BSSID, RSSI ve kanal bilgilerini çıkarır.
""")

        elif choice == "3":
            get_live_networks_from_user()

        elif choice == "4":
            analyze_latest_pcap()

        elif choice == "5":
            analyze_all_pcaps()

        elif choice == "6":
            show_last_summary()

        elif choice == "7":
            show_saved_report()

        elif choice == "8":
            print("Program sonlandırıldı.")
            break

        else:
            print("Geçersiz seçim. Lütfen 1-8 arasında seçim yapınız.")


main_menu()
