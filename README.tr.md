# Crypto Virus Defense Shield (CVDS) - Türkçe

![Build](https://github.com/KeygenLTD/crypto-virus-defense-shield/actions/workflows/build.yml/badge.svg)
![Lisans: MIT](https://img.shields.io/badge/Lisans-MIT-green.svg)

**Antivirüs virüsü siler. Shield dosyalarını kurtarır.**

Açık kaynak **davranışsal** fidye yazılımı savunma çatısı. İmzaya dayalı antivirüsler ve tek ailelik çözücülerin aksine, CVDS şifrelemeyi *olduğu anda* durdurur — yem dosya (honeypot) + gerçek zamanlı CryptoAPI kancası ile — ve RAM'de AES anahtarlarını avlar.

> **Durum:** v0.2 — Honeypot + davranışsal yakalama çalışıyor. Sistem tepsisi + çoklu dil (TR/EN) eklendi. EXE GitHub Actions ile otomatik derleniyor.

### Neden CVDS?
Antivirüs yeni virüsü tanımaz (imza yoksa). CVDS virüs ne olursa olsun `CryptEncrypt` çağırdığı anda yakalar.

### Hızlı Başlangıç (Güvenli Demo)
Sadece `.../Temp/opencode/crypto-test` klasörüne dokunur.

```bash
pip install -r requirements.txt
python src/interceptor/detector.py  # Sistem tepsisinde kalkan belirir
python src/simulator/fake_ransomware.py  # -> [SHIELD] Tehdit algılandı!
```

### İndir
Releases kısmından `CryptoVirusDefenseShield.exe` indir — kurulum yok, çift tıkla sağ altta çalışır. Dil: Tepsi -> Language -> TR/EN.

### Dil Desteği
`sistem dili TR ise otomatik Türkçe`, değilse İngilizce. `locales/tr.json` ve `en.json` var. Yeni dil için `locales/fr.json` ekle, AI placeholder oluşturur.

English version: [README.md](README.md)
