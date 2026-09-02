# Crypto Virus Defense Shield (CVDS) — Türkçe

**Windows için son savunma hattı fidye yazılımı kalkanı.** CVDS artık sabit bir `%TEMP%`
demo klasörünü değil; Masaüstü, Belgeler, İndirilenler, resim/video/müzik klasörleri,
OneDrive ve sistem dışı veri disklerini izler.

CVDS, Microsoft Defender’ın yerine geçmez. Defender, güncelleme/yama yönetimi, MFA,
çevrimdışı ve geri dönüşü test edilmiş yedekler ile olay müdahale planının yanında çalışır.

> **Durum:** v0.3.0 sürüm adayı. Birim testleri gerçek; Windows Defender politikaları,
> süreç askıya alma, bellek dökümü, kurulum paketi ve paketlenmiş EXE’ler Windows CI işi
> geçmeden yayımlanmış/kanıtlanmış sayılmaz. Repoda canlı zararlı yazılım bulunmaz.

## v0.3 gerçekte ne yapıyor?

- Her korunan köke kuruluma özel, rastgele adlandırılmış üç gizli yem dosya koyar.
- Yem değişikliği, kısa sürede çok dosya yazma, uzantı değişikliği, yüksek entropili çıktı,
  sistem geri yükleme silme komutları ve doğrulanmış aile göstergelerini birlikte puanlar.
- Olayı önce açık dosya tanıtıcısıyla, sonra aileye özgü süreç adıyla, son olarak aynı anda
  en çok yazan süreçle ilişkilendirir. Yeterli birleşik güven yoksa süreç silmez/durdurmaz.
- Yüksek güvenli şüphelinin süreç ağacını askıya alır; Windows minidump alır ve okunabilen
  özel bellekte yapısal olarak geçerli genişletilmiş AES-128/192/256 anahtar çizelgesi arar.
- Bulunan değerleri **doğrulanmamış anahtar adayı** olarak kaydeder. Bilinen bir dosyayı
  çözdüğü doğrulanmadan “şifreyi çaldı/kurtardı” demez; anahtar yakalama garanti değildir.
- Masaüstüne `CVDS Acil Temizleme` kısayolu ekler. Yalnız kaydedilmiş süreç kimliği ve dosya
  karması eşleşirse süreç ağacını sonlandırır, Windows/Program Files/ProgramData dosyalarını
  reddeder, şüpheliyi karantinaya taşır, birebir eşleşen Run/RunOnce kalıcılığını kaldırır
  ve Defender taraması ister.

Eski belgelerde geçen CryptoAPI kancası mevcut değildi; o iddia kaldırıldı. v0.3’ün ana
yaklaşımı aileden bağımsız davranış + yem dosya + güvenli süreç ilişkilendirmedir.

## Bu virüsler nereden bulaşıyor, neyi engelliyoruz?

Kurulumdaki varsayılan **Dengeli Giriş Kalkanı**, mevcut Defender ASR politikasını silmeden
18 CVDS kuralını birleştirir. Bulut koruması, ilk görüşte engelleme, PUA, Ağ Koruması,
davranış/script/arşiv/çıkarılabilir sürücü taraması açılır. `strict` profili, dengeli profilde
uyumluluk için yalnız denetlenen kuralları da engellemeye çevirir.

| Bulaşma yolu | Dengeli profilde yapılan | Kalan açık / yapılması gereken |
|---|---|---|
| E-posta/webmail eki, ZIP, EXE, script | E-posta kaynaklı çalıştırılabilir içerik ile Office/Outlook alt süreçleri engellenir | Parolalı arşiv veya farklı istemci yine bulut/Defender tespitine kalabilir |
| Zararlı Word/Excel/PDF | Office’in EXE üretmesi, kod enjekte etmesi, makro Win32 çağrısı ve Adobe Reader alt süreçleri engellenir | Gerçek iş makroları önce uyumluluk testinden geçirilmeli |
| Sahte güncelleme, crack, zararlı reklam/link | Ağ Koruması, PUA, bulut ve ilk görüşte engelleme; az görülen/güvensiz EXE dengelide denetlenir, sıkıda engellenir | İmzalı veya ele geçirilmiş tedarikçi yazılımı itibar kontrolünü aşabilir |
| JS/VBS/PowerShell yükleyici | JS/VBS’nin indirdiği EXE’yi başlatması engellenir; AMSI/script taraması açık; gizlenmiş script dengelide denetlenir | Denetim olayı incelenmeli veya sıkı profil kullanılmalı |
| USB / çıkarılabilir disk | Güvensiz/imzasız süreç çalıştırma engellenir ve disk taraması açılır | Güvenilir imzalı zararlı hâlâ mümkün |
| LSASS parola/NTLM karma çalma | LSASS kimlik bilgisi hırsızlığı engellenir | Önceden çalınmış VPN/RDP hesabı için MFA, IP izin listesi ve hesap izleme gerekir |
| PsExec, WMI ve RMM ile ağda yayılma | Geri yükleme silme komutları izlenir; PsExec/WMI ve WMI kalıcılığı dengelide denetlenir, sıkıda engellenir | Dengeli profil gerçek yönetim araçlarını bozmamak için bunları otomatik kesmez |
| Açık/güncellenmemiş VPN, firewall veya web uygulaması | Ağ Koruması ve savunmayı kapatmakta kullanılan zayıf sürücü engeli saldırı sonrasını zorlaştırır | CVDS yama yöneticisi ya da çevre güvenlik duvarı değildir; servis yamalanmalı, sınırlandırılmalı ve MFA kullanılmalı |

Domain/Intune ilkesi ya da Tamper Protection yerel ayarı reddederse CVDS hatayı gösterir;
koruma açılmış gibi davranmaz. Program kaldırıldığında, bilgisayarı zayıflatmamak için Defender
korumaları otomatik kapatılmaz.

Resmî kural kaynağı: [Microsoft Defender ASR referansı](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference).

## Hangi fidye yazılımı ailelerinde etkili?

Aşağıdaki değerler **canlı zararlı örnekleriyle bağımsız tespit oranı sertifikası değildir**.
v0.3’te bulunan Windows sinyallerinin mühendislik kapsamını anlatır. Bilinmeyen bir aileyi
yem ve toplu şifreleme davranışı yakalayabilir; aile adı yalnız güvenilir gösterge eşleşirse
eklenir.

| Aile | İzlenen göstergeler | Beklenen Windows kapsamı | Sınır / resmî kaynak |
|---|---|---|---|
| Medusa | `.medusa`, `!!!READ_ME_MEDUSA!!!.txt`, `gaze.exe`, geri yükleme silme | **Yüksek** | Linux/ESXi payload’ı korunmaz. [CISA AA25-071A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |
| Gunra | `.CRYPT`, `R3ADM3` | **Orta** aile tanıma; **yüksek** genel davranış | `.crypt` tek başına belirsizdir. [CISA AA26-222A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a) |
| Interlock | `.interlock`, `.1nt3rlock`, `!__README__!.txt` | **Yüksek** | Yalnız Windows encryptor yolu. [CISA AA25-203A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a) |
| Akira | `.akira`, `.akiranew`, aile fidye notları | **Yüksek** | Yeni varyant göstergeleri değiştirebilir. [CISA AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a) |
| Play | `.PLAY`, `ReadMe.txt` | **Orta** aile tanıma; **yüksek** genel davranış | `ReadMe.txt` tek başına işlem yaptırmayacak kadar geneldir. [CISA AA23-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a) |
| RansomHub | `How To Restore Your Files.txt`, genel davranış | **Orta** | Değişken uzantı nedeniyle aile tanıma geç kalabilir. [CISA AA24-242A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a) |
| Black Basta | `.basta`, genel fidye notu | **Orta/Yüksek** | Genel `readme.txt` kasıtlı düşük puanlıdır. [CISA AA24-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a) |
| LockBit 3.0 | `*.README.txt`, genel davranış | **Orta** | Kurban başına rastgele kimlik/uzantı erken aile tanımayı sınırlar. [CISA AA23-075A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a) |
| Rhysida | `.rhysida`, `CriticalBreachDetected.pdf` | **Yüksek** | Yalnız Windows encryptor yolu. [CISA AA23-319A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a) |
| BianLian | `.bianlian`, genel davranış | **Sınırlı/Yüksek** | Şifreleme yaparsa yüksek; yalnız veri çalıp tehdit ederse kalkanın kapsamı dışıdır. [CISA AA23-136A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a) |
| CL0P | `.Clop`/`.Cl0p` türleri, `ClopReadMe.txt` | **Orta/Yüksek** | Yerel şifrelemeyi durdurabilir; sunucu tarafı veri hırsızlığını geri alamaz. [FortiGuard Labs](https://www.fortinet.com/blog/threat-research/ransomware-roundup-cl0p) |
| Bilinmeyen/yeni aile | Yem, toplu aktivite, entropi, uzantı değişimi, yazan süreç | **Davranışa bağlı** | Yavaş/seçici, uzaktan, Linux/ESXi veya yalnız veri hırsızlığı yapan saldırı kaçabilir |

Makinece okunan profil ve kaynaklar `rules/ransomware_families.json` içindedir.

## Kurulum ve kullanım

v0.3.0 Windows iş akışı geçtikten sonra Releases bölümünden:

- `CVDS-Setup-0.3.0.exe`: ajan + masaüstü acil temizleme + başlangıç + isteğe bağlı Defender
  korumaları,
- `CryptoVirusDefenseShield.exe`: taşınabilir ajan,
- `CVDSEmergencyCleanup.exe`: korumalı acil temizleyici.

Olay kayıtları `%LOCALAPPDATA%\CVDS` altında tutulur. Bellek dökümü ve anahtar adayları hassas
olay müdahale kanıtıdır.

```powershell
CryptoVirusDefenseShield.exe --status
CryptoVirusDefenseShield.exe --enable-cfa
CryptoVirusDefenseShield.exe --enable-entry-shield balanced
CryptoVirusDefenseShield.exe --enable-entry-shield strict
```

## Güvenli geliştirici testi

Simülatör rastgele klasöre dokunmayı reddeder. Yalnız adı `cvds-safe-simulation` olan ve tam
güvenlik işaretini içeren klasördeki kendi örneklerini değiştirir.

```powershell
python -m pip install -r requirements.txt pytest
python src/simulator/fake_ransomware.py --prepare

$env:CVDS_PROTECTED_ROOTS = "$env:TEMP\cvds-safe-simulation"
$env:CVDS_STATE_DIR = "$env:TEMP\cvds-safe-state"
python src/interceptor/detector.py --no-tray --response-mode alert

# İkinci PowerShell penceresi:
python src/simulator/fake_ransomware.py --run
python src/simulator/restore.py
python -m pytest -q
```

`--response-mode alert` yalnız zararsız geliştirme simülasyonu içindir. Üretimde varsayılan,
yüksek güvenli süreci askıya almaktır.

## Bilinen sınırlar

- Yönetici yetkili saldırgan kullanıcı modu ajanını kapatabilir; CFA/ASR ayrı işletim sistemi
  katmanı ekler.
- Alarmdan önce bazı dosyalar değişebilir. CVDS geri alma sistemi değildir.
- AES adayı ancak genişletilmiş çizelge okunabilir bellekte kaldıysa bulunur. ChaCha, özel
  kripto, donanım anahtarı, dosya başına anahtar, açık anahtarla sarma veya hızlı bellek silme
  bu yöntemi boşa çıkarabilir.
- Anahtar adayı otomatik çözücü değildir. Döküm, şifreli/özgün örnek, metadata ve olay JSON’u
  adli doğrulama için korunmalıdır.
- Yavaş/seçici şifreleme, ağ tarafı şifreleme, Linux/ESXi ve saf veri hırsızlığı başka
  kontroller gerektirir.

Güvenlik açığını herkese açık issue ile değil, GitHub `Security -> Report a vulnerability`
üzerinden özel bildirin. Canlı zararlı dosyası yüklemeyin.

[English README](README.md) · MIT © 2026 CVDS Contributors
