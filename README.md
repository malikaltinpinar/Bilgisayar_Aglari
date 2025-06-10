🛡️ Proje Özeti
Bu proje, ağ üzerinden dosya gönderimini güvenli ve bütünlüğü korunmuş şekilde gerçekleştirmeyi amaçlayan bir istemci-sunucu sistemidir. AES ve RSA algoritmalarıyla şifreleme yapılmakta, SHA-256 ile bütünlük kontrolü sağlanmaktadır. Ayrıca Scapy kütüphanesi kullanılarak IP başlık alanlarında manuel işlemler gerçekleştirilmiştir. Performans testleri ping, iperf, tc ve Wireshark ile ölçülüp analiz edilmiştir.
⚙️ Özellikler
✅ AES-256 + RSA-2048 ile çift aşamalı şifreleme

✅ SHA-256 ile dosya bütünlüğü doğrulama

✅ Dosya parçalama ve yeniden birleştirme (1024 byte)

✅ Scapy ile düşük seviyeli IP başlığı manipülasyonu (TTL, Checksum vs.)

✅ Wireshark ile MITM saldırısı simülasyonu ve trafik analizi

✅ Ağ performans testi (ping, iperf, tc)

✅ Basit GUI (Tkinter ile dosya seçme arayüzü)

📂 Proje Yapısı

📁 secure-transfer/

client.py # Dosya şifreleme ve gönderme işlemleri

server.py # Şifre çözme, doğrulama ve kayıt işlemleri

common.py  # AES, RSA, SHA256 fonksiyonları ve parçalama işlemleri

scapy_test.py # IP başlıklarının manuel olarak işlendiği test

file_to_send # Gönderilecek örnek dosya

received_file # Alınan ve çözülen dosya

server_public.pem  # Sunucunun açık anahtarı

🚀 Kullanım
1. Gereksinimler
Python 3.x
pycryptodome, scapy, tkinter
pip install pycryptodome scapy
2. Sunucuyu Başlatın
 python server.py
3. İstemciyi Çalıştırın
 python client.py
file_to_send isimli dosya gönderilir, sunucu tarafından received_file olarak kaydedilir.

📊 Ağ Performans Testleri

ping: Ortalama RTT ≈ 0.5ms (localhost)
iperf: Kablosuz ≈ 300 Mbps, Kablolu ≈ 900 Mbps
tc: %5 paket kaybı ve gecikme simülasyonları başarıyla test edilmiştir.

🧪 MITM Saldırı Simülasyonu

Sahte sunucu ile MITM senaryosu test edildi.
RSA anahtarı olmadan AES anahtarı çözülemediği için saldırı başarısız oldu.
Trafik Wireshark ile şifreli ve okunamaz olarak gözlemlendi.

📚 Kaynaklar

Stallings, W. (2017). Data and Computer Communications, Pearson.
Scapy Documentation – https://scapy.readthedocs.io/
Wireshark User Guide – https://www.wireshark.org/docs/
PyCryptodome Docs – https://pycryptodome.readthedocs.io/
