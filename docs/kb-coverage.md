# Bilgi tabanı kapsaması

Ölçüm: EVTX-ATTACK-SAMPLES commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`, taktik klasörü başına
üretilmiş 10 CSV, toplam 5.352 tespit, 64 farklı `(kanal, EventID)` çifti.

Yeniden üretmek için:

```powershell
.\.venv\Scripts\python.exe -m evtx_triage.cli kb check --csv "data\hayabusa_csv\by_tactic\credential_access.csv"
.\.venv\Scripts\python.exe scripts\eid_frequency.py "data\hayabusa_csv\by_tactic" --uncovered-only
```

## Durum

| Katman | Kapsama |
|---|---|
| Olay sözlüğü | **55 / 64 çift**, **5.327 / 5.352 satır (%99,5)** |
| ATT&CK taktik kısaltmaları | **14 / 14 (%100)** |
| ATT&CK etiketleri (`MitreTags`) | **%100** — 1.877 kayıtlık katalog (858 teknik, 191 grup, 828 yazılım) |

Sözlük dağılımı: Sysmon 21, Security 29, BITS-Client 1, System 1, PowerShell 1, Defender 1, Application 1.

| Tarih | Değişiklik | Kapsama |
|---|---|---|
| 2026-09-14 (Faz 3) | İlk sözlük | 54 çift, %96,4 |
| 2026-09-15 | **BITS-Client 59 eklendi** (kullanıcı kararı) | 55 çift, %99,5 |

## BITS-Client 59 nasıl kaynaklandı

Bu olay kimliği için anlamı doğrudan veren yayımlanmış bir sayfa **yok**. Kural "kaynak zorunlu, tahmin yok"
olduğu için kayıt şöyle doğrulandı:

1. **Anlam:** Windows'un kendi olay sağlayıcı manifestosundan okundu
   (`(Get-WinEvent -ListProvider Microsoft-Windows-Bits-Client).Events`). Olay 59'un şablonu:
   *"BITS started the %2 transfer job that is associated with the %4 URL"* (makinede Türkçe yerelleştirilmiş hâli görüldü).
   Aynı manifestoda 60 ve 61 "aktarımı durdurdu" olaylarıdır.
2. **Alanlar:** korpustaki 165 olayın `AllFieldInfo` anahtarlarından okundu:
   `Id, name, transferId, url, peer, fileTime, fileLength, bytesTotal, bytesTransferred, bytesTransferredFromPeer`.
3. **Kaynak URL'leri:** BITS işinin ne olduğunu anlatan Microsoft Learn BITS portalı ve tespit verisi olarak
   "BITS-Client operational events" kanalını anan ATT&CK T1197 sayfası. İkisi de HTTP 200 ile doğrulandı.

> Sınır: kaynak URL'leri olay 59'un *kimlik–anlam eşlemesini* değil, BITS'in ne olduğunu ve neden izlendiğini
> belgeliyor. Eşlemenin kanıtı manifesto okumasıdır ve kaydın YAML yorumunda yazılıdır.

Korpusa dair not: 165 olayın **tamamı** Hayabusa tarafından `informational` ("Bits Job Created") işaretlenmiş ve
incelenen örneklerin çoğu meşru güncelleyicilere ait (Google Update, Windows yapılandırma indirmeleri).
Sözlük kaydı olayı açıklar; kötücül olup olmadığına URL ve iş adı üzerinden analist karar verir.

## Kapsanmayan 9 çift ve gerekçesi

Kural: *"Sözlük ve rehber içeriğinde kaynak URL zorunludur... Emin olmadığın EventID bilgisini
doldurma."* Aşağıdaki olaylar için **güvenilir ve doğrulanabilir bir kaynak bulunamadı**, bu yüzden sözlüğe
yazılmadılar ve raporda `UNKNOWN` olarak görünüyorlar. Kullanıcı kararıyla (2026-09-15) şimdilik böyle kalıyorlar.

| Satır | Kanal | EventID | Neden yazılmadı |
|---:|---|---|---|
| 11 | `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | 1149 | RDS olay kimlikleri için resmî referans sayfası bulunamadı. |
| 5 | `Application` | 325, 326, 327 | ESENT (veritabanı motoru) olayları; kimlik bazlı referans yok. |
| 4 | `Application` | 15457 | MSSQL yapılandırma değişikliği olduğu düşünülüyor ama doğrulanamadı. |
| 2 | `System` | 104 | System kanalında olay günlüğü temizleme; Security 1102'nin karşılığı ama referans sayfası yok. |
| 2 | `Application` | 1040, 1042 | MsiInstaller işlem olayları; kimlik bazlı referans bulunamadı. |
| 1 | `Application` | 33205 | MSSQL denetim olayı olduğu düşünülüyor ama doğrulanamadı. |

Toplam: **25 satır, %0,5**.

> Bunlar hatalı değil, **bilinçli boşluk**. Araç bu olayları atmıyor: raporda tüm alanlarıyla görünüyorlar,
> yalnızca sözlük başlığı yerine `UNKNOWN` yazıyor ve `coverage.unknown_pairs` altında listeleniyorlar.
> `tests/unit/test_samples.py` bu listenin sessizce değişmesini engelliyor.

BITS 59'da kullanılan manifesto yöntemi 1149, 104 ve 325–327 için de uygulanabilir. Bu, "yayımlanmış kaynak"
yerine "sağlayıcı manifestosu + korpus gözlemi" kanıtını kabul etmek anlamına gelir ve ayrı bir karardır.

## Teknik not: kaldırılmış ATT&CK kimlikleri

Sigma kuralları ATT&CK'nin eski sürümlerinden kimlikler taşıyor. Örnek: `T1070.001`
(*Clear Windows Event Logs*) v19.2 matrisinde yok. Katalog bu kayıtları **atmıyor**,
`retired: true` ile işaretliyor (179 kayıt), böylece analist "bilinmeyen kimlik" yerine
"ATT&CK 19.2'de kaldırılmış" bilgisini görüyor.

`MitreTags` yalnızca teknik içermiyor; grup (`G0046`) ve yazılım (`S0002` = Mimikatz)
kimlikleri de geliyor. Katalog üçünü de taşıyor ve `kind` alanıyla ayırıyor.
