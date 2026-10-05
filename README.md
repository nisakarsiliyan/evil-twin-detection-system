# Evil Twin Tespit Sistemi

Python ile geliştirilmiş, kablosuz ağlarda potansiyel **Evil Twin (Sahte Wi-Fi)** saldırılarını tespit etmeye yönelik bir analiz sistemidir.

## Proje Hakkında

Sistem; kablosuz ağlara ait **SSID, BSSID, RSSI, kanal ve güvenlik türü** gibi bilgileri analiz ederek şüpheli ağları belirlemeyi amaçlamaktadır.

Aynı SSID'nin farklı BSSID'ler üzerinden yayınlanması, açık (OPEN) ağ kullanımı, yüksek sinyal gücü ve kanal farklılıkları gibi kriterler değerlendirilerek bir **risk skoru** oluşturulur.

## Özellikler

* Aynı SSID'ye sahip farklı BSSID'leri tespit etme
* Wi-Fi ağlarının risk analizi
* Risk skoru ve risk seviyesi oluşturma
* SSID, BSSID, RSSI, kanal ve güvenlik türü analizi
* PCAP dosyalarından kablosuz ağ bilgilerini çıkarma
* Şüpheli ağları JSON formatında kaydetme
* Analiz sonuçlarını CSV formatında raporlama
* Simülasyon verileri ile test yapabilme
* Manuel ağ verisi girerek analiz yapabilme

## Kullanılan Teknolojiler

* Python
* tcpdump
* PCAP
* JSON
* CSV
* Regular Expressions (Regex)

## Risk Analizi

Sistem aşağıdaki kriterleri değerlendirerek risk skoru oluşturur:

* Aynı SSID'nin farklı BSSID'lerle görülmesi
* Referans ağdan farklı kanal kullanılması
* Ağın açık (OPEN) olması
* Anormal derecede yüksek sinyal gücü

Risk seviyeleri:

* **0:** Güvenli
* **1–39:** Düşük Risk
* **40–69:** Orta Risk
* **70–100:** Yüksek Risk

## Çalıştırma

Python 3 ile çalıştırılabilir:
"python3 final_version.py"

Program çalıştırıldığında kullanıcıya farklı analiz seçenekleri sunulur.

## Proje Türü

Bu proje, **Adli Bilişim Mühendisliği bitirme projesi** kapsamında geliştirilmiştir.
