# ADR-0002 — Hayabusa girdi sözleşmesi

- **Durum:** Kabul edildi (Faz 0 / A, 2026-09-14)
- **Kaynak:** Varsayım değil, gerçek çıktı ölçümü. Hayabusa v4.1.0 (`ProductVersion` doğrulandı),
  EVTX-ATTACK-SAMPLES commit `4ceed2f4706daf601c212a8f91c113dd85349a2c` (278 EVTX), 5.360 tespit.
- **Ortam:** Windows 11 Home, PowerShell 5.1.

## 1. Kilitlenen sürümler

| Öğe | Değer |
|---|---|
| Hayabusa | v4.1.0, `hayabusa-4.1.0-win-x64.zip` |
| Zip SHA256 | `4d304cc5baaa750ed08cc24b7b89c58ea058740c7e344502d7b82554637543a8` (yayıncı özetiyle birebir) |
| Zip boyutu | 44.765.237 bayt |
| Kural sayısı | 4.984 `.yml` (zip ile gelen; `update-rules` **çalıştırılmadı**) |
| Kurulum yolu | `C:\tools\hayabusa-4.1.0\hayabusa-4.1.0-win-x64.exe` |
| Örnek veri | EVTX-ATTACK-SAMPLES @ `4ceed2f4706daf601c212a8f91c113dd85349a2c` (2023-01-24), 278 EVTX, 67 MB |

Defender hiçbir dosyayı karantinaya almadı (`git status --short` boş).

## 2. Zorunlu Hayabusa komutu

```powershell
hayabusa.exe dfir-timeline -f <EVTX> -p all-field-info-verbose -U -O -w -q -C -b -A -o <CSV>
```

`-b` **zorunludur** (gerekçe §5). `-U` ve `-O` birlikte kabul edilir; `-O` zaten "Always UTC" der.

### Değişiklik (Faz 7, 2026-09-15): `-A` zorunlu

`-A, --enable-all-rules` kanal filtresini kapatır. Bu bayrak olmadan Hayabusa, taranan dosyada gördüğü kanallara
göre kural açar. 4.658 kuralın 1.862'si açık kaldı ve **tek dosya taramasında tespit kaybı ölçüldü**:

| Ölçüm | `-A` yok | `-A` var |
|---|---|---|
| `Credential Access/tutto_malseclogon.evtx`, tek dosya | **12** tespit, 49 sn | **19** tespit, 2,5 sn |
| Kaybolan 7 tespitten biri | `Uncommon GrantedAccess Flags On LSASS` (**medium**, Sysmon 10) | geliyor |
| 278 örnek, dosya başına `-A` ile, tüm-dizin koşusuyla karşılaştırıldı | — | **275/275 aynı** (3 örnek Defender engeli, aşağıda) |
| Eval setinin diğer 9 CSV'si ve referans CSV | — | içerik değişmedi |

Tüm dizin taranınca filtre bütün dosyaların kanal birleşimiyle kurulduğu için kayıp görünmüyordu. Faz 0 eval
CSV'leri ise dosya başına üretildi, bu yüzden tutto 7 tespit eksikti. Hız farkının nedeni de filtrenin kendisi:
filtreyi kurmak tek dosyada 46 sn sürüyor.

**Etkisi:**
- Eval CSV'leri `-A` ile yeniden üretildi (`scripts/generate_sample_csvs.py`, sürümler ve hash'ler `eval/samples.lock`).
  Tutto 12 → 19 satır; gruplama etiketi değişmeden geçiyor.
- Araç CSV'nin `-A` ile üretilip üretilmediğini içerikten anlayamaz (başlık aynı). README ve raporun
  `provenance.hayabusa_flags` alanı komutu `-A` ile gösterir. Kullanıcı `-A`'yı unutursa sessiz tespit kaybı olur.
  Bu bir sınırlılıktır.

**Defender (dosya başına üretimde, 2026-09-15):** 278 örneğin 3'ü üretilemedi. Defender kapatılmadı, dosyalar
yeniden adlandırılarak atlatılmadı:

| Örnek | Ne oldu |
|---|---|
| `Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx` | Hayabusa'nın **komut satırında** `Invoke-Mimikatz` geçtiği için süreç başlatılmadı (ThreatID 2147725502) |
| `Execution/Sysmon_Exec_CompiledHTML.evtx` | çıktı CSV'si okunamadı (içerik taraması) |
| `Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx` | çıktı CSV'si okunamadı (Faz 4'teki ThreatID 2147822433 ile aynı örnek) |

**Yasak bayraklar** — çıktıyı ayrıştırılamaz hâle getirirler:

| Bayrak | Neden |
|---|---|
| `-R, --remove-duplicate-data` | Tekrar eden alan verisini `"DUP"` ile değiştirir → veri kaybı |
| `-M, --multiline` | `AllFieldInfo` ayırıcısını satır sonuna çevirir |
| `-S, --tab-separator` | `AllFieldInfo` ayırıcısını sekmeye çevirir |
| `-X, --remove-duplicate-detections` | Tespit siler |

`-F, --no-field-data-mapping` **kullanılmaz**: alan değeri eşlemesi açık kalır, yani değerler
insan-okunur hâlde gelir (ör. `TokenElevationType: FULL_TOKEN`, ham `%%1936` değil). Sözlükteki
`key_fields` beklenen değerleri buna göre yazılır.

## 3. Gerçek başlık (ölçüldü)

```
"Timestamp","RuleTitle","Level","Computer","Channel","EventID","MitreTactics","MitreTags","OtherTags","RecordID","AllFieldInfo","RuleFile","RuleID","EvtxFile"
```

14 kolon. `-b` başlığı **değiştirmez**; iki varyantta da birebir aynıdır.
Başlık satırları Faz 0'da gerçek çıktıdan alındı; ayrıştırıcı bu ADR'deki kümeyi bekler
(`src/evtx_triage/ingest/hayabusa_csv.py`, `EXPECTED_COLUMNS`).

> **Plandaki varsayılan kolon sırası yanlıştı.** Kolon kümesi aynı, sıra farklı:
> varsayımda `RuleTitle` 10., gerçekte 2.; `Level` 5. değil 3.; `Computer`/`Channel`/`EventID` iki basamak kaymış.
> Ayrıştırıcı başlığı isimle eşler, sıraya güvenmez; yine de başlık bu satırdan farklıysa açık hata verir.

## 4. Dosya biçimi (ölçüldü)

| Özellik | Değer | Ölçüm |
|---|---|---|
| Kodlama | UTF-8, **BOM yok** | ilk 3 bayt `34 84 105` = `"Ti` |
| Satır sonu | **LF** (CR yok) | 5,9 MB dosyada CR=0, LF=5361 |
| Gömülü satır sonu | **yok** | LF sayısı = kayıt + 1 (5360+1) |
| Tırnaklama | **seçici** | `EventID` ve `RecordID` tırnaksız; metin alanları tırnaklı; boş alan `""` |

→ Python: `open(path, newline="", encoding="utf-8")` + stdlib `csv`. Elle `split(",")` yapılamaz.
BOM beklenmediği için `utf-8-sig` gerekmez, ama zararsızdır.

## 5. Kısaltmalar: `-b` neden zorunlu

`-b` yalnızca `Level` ve `Channel` kolonlarını etkiler. Tespit sayıları iki varyantta aynıdır (5.360).

**Level — 1:1, kayıpsız:**
`info→informational`, `low→low`, `med→medium`, `high→high`, `crit→critical`
(`emergency` bu veri setinde görülmedi.)

**Channel — çok-tek eşleme, KAYIPLI.** `rules/config/channel_abbreviations.txt` (46 eşleme) içinde
aynı kısaltmaya giden birden fazla kanal var:

- `AppLocker` → 4 kanal (`MSI and Script`, `EXE and DLL`, `Packaged app-Deployment`, `Packaged app-Execution`)
- `SecMitig` → 2 kanal (`KernelMode`, `UserMode`)

Ayrıca `generic_abbreviations.txt` sözcük düzeyinde kısaltma (Microsoft→MS, Operational→Op, …) uygular,
yani tabloda olmayan kanallar için de kısaltma türetilebilir; çakışma riski açıktır.

Sözlük anahtarımız `(channel_canonical, event_id)` olduğundan kısaltmalı kanal adı bu anahtarı tekil
çözemez. **Karar:** araç yalnızca `-b` ile üretilmiş CSV kabul eder. Kısaltmalı bir CSV verilirse
(`Level` değeri `info`/`med`/`crit` ya da `Channel` değeri kısaltma tablosunda geçiyorsa) açık hata verilir
ve doğru komut mesajda gösterilir. Böylece `knowledge/` altında kanal alias tablosu tutmaya da gerek kalmaz —
bu aynı zamanda hayabusa-rules (DRL 1.1) içeriğini repoya kopyalama ihtiyacını ortadan kaldırır (§14 lisans kuralı).

**Ölçülen kanal değerleri (kısaltmasız):**
`Microsoft-Windows-Sysmon/Operational` (3814), `Security` (1311), `Microsoft-Windows-Bits-Client/Operational` (165),
`Application` (22), `Microsoft-Windows-PowerShell/Operational` (13), `Microsoft-Windows-Windows Defender/Operational` (13),
`System` (11), `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` (11).

## 6. MitreTactics — `-b` bu kolonu etkilemez

`MitreTactics` **her zaman kısaltmalıdır**; `-b` bu kolonu açmaz (5.360 kaydın tamamında iki varyant aynı).
Çoklu değer ayırıcısı `AllFieldInfo` ile aynı: **` ¦ `** (ör. `PrivEsc ¦ Stealth`).
Kayıtların %51'inde (2.752) boştur.

Kısaltma tablosu Hayabusa'nın `config/mitre_tactics.txt` dosyasındadır; **repoya kopyalanmaz**,
`knowledge/attack/tactics_abbrev.yaml` kendi cümlelerimizle ve ATT&CK atfıyla yazılır.

> **Düzeltme (Faz 2, 2026-09-14).** Bu bölümün ilk hâli `Stealth` ve `DefImpair` için
> "gerçek ATT&CK taktiği değil, Hayabusa'ya özgü" diyordu. **Yanlıştı.** attack.mitre.org
> üzerinden doğrulandı (ATT&CK v19.2): **TA0005'in güncel adı `Stealth`**tir (eski adı Defense Evasion)
> ve **TA0112 `Defense Impairment`** v19 ile eklenmiş gerçek bir taktiktir. Hayabusa güncel adları kullanıyor.
>
> - `attack.stealth` ve `attack.defense-evasion` etiketlerinin ikisi de `Stealth` üretir; bu bir hata değil,
>   eski ve yeni Sigma etiketinin aynı taktiğe (TA0005) işaret etmesidir. Geri dönüş belirsizliği yoktur.
> - `DefImpair` → TA0112.

Tüm örnek setinde gözlenen 14 kısaltma:
`Collect, Stealth, PrivEsc, Exec, Persis, CredAccess, Disc, LatMov, C2, DefImpair, InitAccess, ResDev, Exfil, Impact`.
(Tek örnekte yalnızca 10'u görülmüştü; tablo tüm sete göre yazıldı.)

## 7. Zaman damgası — üç biçim varyantı

| Sayı | Biçim | Örnek |
|---|---|---|
| 5.352 | 6 hane mikrosaniye | `2019-03-18T22:15:49.645889Z` |
| 7 | kesir **yok** | `2019-03-18T22:15:49Z` |
| 1 | 3 hane milisaniye | `2019-03-18T22:15:49.645Z` |

Hepsi `Z` ile biter, hepsi UTC. Sabit `strptime` biçimi **kırılır**;
`datetime.fromisoformat` (Python 3.11) üç varyantı da okur ve `Z` sonekini kabul eder.
`--help`'teki 7 haneli örnek (`.1234567Z`) gerçek çıktıda görülmedi; görülürse `fromisoformat` fazlalığı kırpar
(mikrosaniye altı kaybolur, sıralama eşitliği §6.2 anahtarıyla çözülür).

Ofsetsiz (naive) zaman damgası **görülmedi**; `--assume-utc` bayrağı yine de gerekli, çünkü garanti değil.

## 8. AllFieldInfo ayrıştırma

- Ayırıcı: **` ¦ `** — U+00A6 (kod noktası 166), boşlukla çevrili. Dosyadaki tek ASCII-dışı karakter budur.
- Parça biçimi: `Anahtar: Değer`, ilk `: ` üzerinden bölünür; değerdeki `:` korunur
  (ör. `NewProcessName: C:\Windows\System32\wbem\WmiPrvSE.exe`).
- **Boş değer olağandır:** `CommandLine: ¦ NewProcessId: 2792` — anahtar vardır, değeri boştur.
  Ayrıştırıcı bu parçayı **atmaz**, boş dize olarak saklar.
- Tekrar eden anahtarlar liste olarak saklanır (plandaki karar korunur).

## 9. Faz 1 referans örneği

`Credential Access\sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx`

| Ölçüt | Değer |
|---|---|
| Tespit | 35 satır (prompt bütçesi için rahat) |
| Seviye | 3 critical, 7 high, 8 medium, 8 low, 5 informational — beş seviye de var |
| Konak | tek: `alice.insecurebank.local` |
| Kanal | tek: `Microsoft-Windows-Sysmon/Operational` (EID 1, 10, 11) |
| Süre | 1,2 dakika |
| Senaryo | LSASS bellek dökümü (Dumpert / AndrewSpecial) — analist doğrulaması kolay |

Seçim gerekçesi: `selection.model_min_level = "medium"` eşiğini gerçekten tetikler; aynı kural 8 kez
tekrarlandığı için `pack` katlamasını da sınar; tek konak/tek kanal olduğundan gruplama Faz 1'de sade kalır.

> İlk aday `Lateral Movement\LM_WMI_4624_4688_TargetHost.evtx` (runbook A8) **elendi**:
> 6 tespitin tamamı `informational`, hiçbir grup modele gitmezdi.

Çok kanallı ikinci örnek Faz 2 için: `Credential Access\tutto_malseclogon.evtx` (19 tespit, 2 kanal).
Çok konaklı gruplama testi için birleşik CSV Faz 4'te üretilecek.

## 10. Kapsam dışı kalan örnekler

278 EVTX'in **251'i** tespit üretti; 27 dosya hiç tespit üretmedi → "Hayabusa kapsamı dışı" olarak
ayrı sayılır (değerlendirme planı). Tüm set taraması 4,3 saniye sürdü, uyarı/hata satırı yok.

## 11. Sözlük önceliği (Faz 3 girdisi)

En sık `(kanal, EventID)` çiftleri — `scripts/eid_frequency.py` bu listeyi üretecek:

| Sayı | Kanal, EventID |
|---|---|
| 2298 | Sysmon/Operational, 1 (process creation) |
| 889 | Security, 5145 (network share object access) |
| 299 | Sysmon/Operational, 8 (CreateRemoteThread) |
| 270 | Sysmon/Operational, 11 (file create) |
| 206 | Sysmon/Operational, 10 (process access) |
| 194 | Sysmon/Operational, 3 (network connection) |
| 171 | Sysmon/Operational, 13 (registry value set) |
| 165 | Bits-Client/Operational, 59 |
| 149 | Sysmon/Operational, 7 (image load) |
| 98 | Security, 5156 (WFP allowed connection) |

İlk 10 çift 5.360 tespitin ~%84'ünü kapsıyor.

## 12. Planda değişmesi gerekenler

1. §6.1 beklenen başlık sırası → bu ADR'deki gerçek sıra. ✔ uygulandı
2. §6.1 "alias tablolarıyla her iki biçimi de destekler" → **yalnızca kısaltmasız (`-b`) girdi kabul edilir**;
   kısaltmalı girdi açık hata. ✔ uygulandı
3. §6.1 zaman biçimi ⚠ → üç varyant, `fromisoformat`. ✔ uygulandı
4. §3 tablosundaki Hayabusa komutu → `-b` eklenir. ✔ uygulandı
