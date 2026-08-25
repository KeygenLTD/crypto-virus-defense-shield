# Crypto Virus Defense Shield (CVDS) - Türkçe

![Build](https://github.com/KeygenLTD/crypto-virus-defense-shield/actions/workflows/build.yml/badge.svg)
![Lisans: MIT](https://img.shields.io/badge/Lisans-MIT-green.svg)

**Antivirüs virüsü siler. Shield dosyalarını kurtarır.**

Açık kaynak **davranışsal** fidye yazılımı savunma çatısı. İmzaya dayalı antivirüsler ve tek ailelik çözücülerin aksine, CVDS şifrelemeyi *olduğu anda* durdurur — yem dosya (honeypot) + gerçek zamanlı CryptoAPI kancası ile — ve RAM'de AES anahtarlarını avlar.

> **Durum:** v0.2 — Honeypot + davranışsal yakalama çalışıyor. Sistem tepsisi + çoklu dil (TR/EN) eklendi. EXE GitHub Actions ile otomatik derleniyor.

### Neden CVDS?
Antivirüs yeni virüsü tanımaz (imza yoksa). CVDS virüs ne olursa olsun `CryptEncrypt` çağırdığı anda yakalar.

### Hızlı Başlangıç

**Kullanıcılar için (kurulum):** Releases'ten `CVDS-Setup-0.2.0.exe` indir -> Kur -> Sağ altta kalkan belirir. Python gerekmez.

**Geliştiriciler için (güvenli demo):** Demo sadece kendi izole test klasörünü kullanır, gerçek dosyalarınıza dokunmaz.
```bash
git clone https://github.com/KeygenLTD/crypto-virus-defense-shield.git
cd crypto-virus-defense-shield
pip install -r requirements.txt
python src/interceptor/detector.py  # Sistem tepsisinde kalkan belirir
python src/simulator/fake_ransomware.py  # -> [SHIELD] Tehdit algılandı!
```

### Dil Desteği
Sistem dili TR ise otomatik Türkçe. Tepsi -> Dil ile değiştirilebilir. Yeni dil seçince ücretsiz API ile otomatik çevrilir.

English version: [README.md](README.md)
