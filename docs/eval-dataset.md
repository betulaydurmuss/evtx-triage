# Değerlendirme veri seti ve sınırlılıkları

Bu belge üç soruya cevap verir: değerlendirmede hangi örnekler var ve neden, bir örnek neden dışarıda,
ve etiketlere ne kadar güvenilebilir.

## 1. Kompozisyon

Kaynak: EVTX-ATTACK-SAMPLES commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`, Hayabusa 4.1.0,
komut ADR-0002 §2 (`-p all-field-info-verbose -U -O -w -q -C -b -A`; `-A` Faz 7'de eklendi, tutto 12 → 19 satır). CSV'ler `data/hayabusa_csv/eval/`
altındadır ve lisans gereği repoya girmez (GPL örnek verisi).

| # | Örnek (EVTX) | CSV satırı | Etiket dosyası |
|---:|---|---:|---|
| 1 | `Credential Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx` | 35 | `dumpert_andrewspecial_memdump.yaml` |
| 2 | `Credential Access/tutto_malseclogon.evtx` | 19 (Faz 6'ya kadar `-A`'sız 12) | `malseclogon_token_theft.yaml` |
| 3 | `Lateral Movement/LM_sysmon_3_12_13_1_SharpRDP.evtx` | 35 | `sharprdp_lateral_movement.yaml` |
| 4 | `Persistence/DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.evtx` | 37 | `dcsync_right_granted.yaml` |
| 5 | `Privilege Escalation/Sysmon_UACME_64.evtx` | 25 | `uacme_akagi_bypass.yaml` |
| 6 | `Privilege Escalation/privesc_roguepotato_sysmon_17_18.evtx` | 13 | `roguepotato_privesc.yaml` |
| 7 | `Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx` | 21 | `mshta_rundll32_execution.yaml` |
| 8 | `Discovery/dicovery_4661_net_group_domain_admins_target.evtx` | 53 | `ad_group_recon.yaml` |
| 9 | `Defense Evasion/DE_1102_security_log_cleared.evtx` | 2 | `security_log_cleared.yaml` |
| 10 | `Defense Evasion/DE_104_system_log_cleared.evtx` | 1 | `system_log_cleared_unknown_event.yaml` |

**Kullanılan: 10 CSV.** `data/hayabusa_csv/eval/` klasöründe ise **11 dosya** bulunur; farkın nedeni §2.

### Setin nasıl oluştuğu (sayı tutarsızlığı sorusuna cevap)

1. İlk liste 10 örnekti.
2. Bunlardan biri (`Defense Evasion/DE_sysmon_1_1102_clear_security_eventlog_wevtutil.evtx`) **repoda yoktu**;
   yol yanlış yazılmıştı, CSV hiç üretilmedi.
3. Biri (`Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx`) üretildi ama **Defender engelledi** (§2).
4. Kalan 8'e iki Defense Evasion örneği eklendi (#9, #10) → 10 kullanılabilir CSV, klasörde 11 dosya.

Taktik bazında üretilen 10 CSV (`by_tactic/`) ve kökteki `reference.csv` bu setten ayrıdır: onlar ingest,
sözlük kapsaması ve determinizm testleri içindir, gruplama etiketleri yalnızca bu 10 örnek içindir.

## 2. Dışarıda bırakılan örnek: meterpreter

| | |
|---|---|
| Örnek | `Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx` |
| Üretilen dosya | `data/hayabusa_csv/eval/lm_sysmon_psexec_smb_meterpreter.csv` (169.742 bayt, diskte duruyor) |
| Olay | Microsoft Defender, dosyayı **ThreatID 2147822433** ile işaretledi (2026-09-15 00:06 ve 00:07) |
| Etki | Dosya okunamıyor: *"Dosya virüslü olduğundan veya istenmeyebilecek yazılım içerdiğinden işlem başarılı bir şekilde tamamlanmadı."* |
| Neden | Engellenen EVTX değil, **bizim ürettiğimiz CSV**. Olay alanlarındaki meterpreter komut satırı dizeleri imzaya takılıyor. |
| Karar | **Defender'a dokunulmadı, istisna eklenmedi, örnek eval setinin dışında.** (araç geliştiricisinin önerisi, kullanıcı onayı 2026-09-15; kural: Defender kapatılmaz) |

Sonuçları:

- Setteki tek **psexec/SMB üzerinden yanal hareket** örneği bu olduğu için o senaryo şu an etiketli değil.
  SharpRDP (#3) yanal hareketi temsil ediyor ama farklı bir teknik.
- `eval/metrics.py` okunamayan CSV'yi çökmeden `skipped ... unreadable CSV` diye raporlar.
- Aynı durum Faz 7'de başka örneklerde de çıkabilir. Üretilen her CSV okunabilirlik açısından kontrol edilmeli
  ve engellenenler bu tabloya eklenmeli.

## 3. Sınırlılık: etiketleri aracı yazan taraf yazdı

**Bu, değerlendirme sonuçlarının yorumunu doğrudan etkiler.**

`eval/labels/expected/` altındaki 10 etiketin tamamını **aracı geliştiren taraf taslak olarak yazdı.**
Plan (Faz 4) etiketlerin kullanıcıyla yazılmasını öngörüyordu. Etiketler gerçek CSV içeriğine
bakılarak yazıldı, ezberden değil. Ama değerlendirilen sistemi yapan taraf referansı da yazınca şu riskler doğar:

1. **Araca göre etiket.** Etiketler, gruplama kodu yazıldıktan ve çıktısı görüldükten sonra yazıldı.
   Araç bir şeyi yanlış anlıyorsa, etiket de aynı yanlışı "doğru" diye kaydedebilir.
2. **Etikete göre araç.** `normalize_user` düzeltmesi, gruplama bu örneklerde "başarısız" göründüğü için yapıldı.
   Düzeltme bence doğru ama aynı örnekler hem hatayı bulmak hem düzeltmeyi onaylamak için kullanıldı.
3. **Beklentinin sonuca uydurulması.** `ad_group_recon` etiketinin beklentisi, araç onu bölünce değiştirildi.
   Değişikliği kullanıcı gerekçesiyle onayladı; yine de bu, döngüselliğin en açık olduğu yer.
4. **Model çıktısının sızması.** Referans örnek (#1) için model yorumu Faz 1'de etiket yazılmadan önce görüldü.
   `must_mention_any` listeleri bundan etkilenmiş olabilir.
5. **Gevşek anahtar kelimeler.** `must_mention_any` listelerinde "log", "system", "run" gibi çok genel kelimeler var.
   Faz 7 model metrikleri bu hâliyle hoşgörülü çıkar.
6. **Hayabusa kural adlarına bağlılık.** Eşleştiricilerin çoğu `rule_title_contains` kullanıyor; kural seti
   güncellenirse etiketler sessizce eşleşmemeye başlayabilir (metrik bunu `MISSING matcher` diye gösterir).

Faz 5'te yazılacak rehber notları ve `eval/golden_queries.yaml` için de aynı sınırlılık geçerli: notları da,
hangi notun hangi soruya uygun olduğunu da aynı taraf yazıyor.

**Bu yüzden:** "grouping as labelled 10/10" ve Faz 5 recall değerleri, **kullanıcı etiketleri doğrulayana kadar
iyimser üst sınır** olarak okunmalıdır. Doğrulanan etiketler dosyanın başına
`# verified-by: <kişi>, <tarih>` satırıyla işaretlenir; metrik raporu doğrulanmış ve doğrulanmamış
etiketleri ileride ayrı sayabilir.

## 4. Elle doğrulama önceliği

Risk sırasına göre. Her satırda CSV'de neye bakılacağı yazılı.

| Öncelik | Etiket | Neden kritik | CSV'de kontrol edilecek |
|---:|---|---|---|
| **1** | `ad_group_recon` | Beklenti araç çıktısından sonra değiştirildi (risk 3). "İki ayrı hikâye" kararının dayanağı. | user01'in 4624 ağ oturumunun `IpAddress` / `WorkstationName` değerleri administrator'ın oturumuyla aynı kaynaktan mı geliyor? Aynıysa aynı operatör iki kimlik kullanıyor olabilir; o zaman "iki hikâye" yanlış olur. *Başlangıç noktası (okundu, yorumlanmadı):* user01'in 4624'ü (R000003) ve 5140'ı (R000004) `10.0.2.17`'den; administrator'ın 4776'sı (R000001) iş istasyonu olarak konağın kendisini (`WIN-77LTAPHIQ1R`) gösteriyor. |
| **2** | `roguepotato_privesc` | Grup `system` altında toplanıyor. Exploit `NT AUTHORITY\LOCAL SERVICE` ile başlayıp `SYSTEM` kabuğu açıyor; `normalize_user` ikisini de `system`'e katladığı için **yetki yükseltme yolu grup başlığında görünmüyor.** | `EID 1` "Hacktool Execution - Imphash" ve "Elevated System Shell Spawned" satırlarının `User` alanları. Bu katlamanın analist için kabul edilebilir olup olmadığı. *Okunan değerler:* R000009 (critical, RoguePotato.exe) `NT AUTHORITY\LOCAL SERVICE`; R000004/R000010/R000013 (nc64.exe, cmd.exe) `NT AUTHORITY\SYSTEM`. |
| **3** | `sharprdp_lateral_movement` | `normalize_user` düzeltmesinden hemen sonra yazıldı (risk 2). Kilit olaylar (Sysmon 12/13) `User` alanı taşımıyor; ieuser'ın grubuna yalnızca "pencerede tek insan hesabı" kuralıyla giriyor. | 7,4 dakikalık pencerenin tamamı gerçekten tek bir RDP oturumu mu? `rule_title_contains` eşleştiricilerinin yakaladığı satırlar kastedilen olaylar mı? |
| **4** | `dumpert_andrewspecial_memdump` | Referans örnek: bütçe, `chars_per_token` ve `CallTrace` kararları hep bunun üzerinde ölçüldü. Model yorumu etiketten önce görüldü (risk 4). | Anahtar olayların doğru seçildiği; `must_mention_any` / `must_not_mention` listelerinin model çıktısından bağımsız olarak mantıklı olduğu. |

Daha düşük öncelik: `dcsync_right_granted`, `uacme_akagi_bypass`, `mshta_rundll32_execution`,
`malseclogon_token_theft` (hikâye tek hesapta ve açık). En düşük: `security_log_cleared` ve
`system_log_cleared_unknown_event` (1–2 olay, "aynı grup" koşulu kendiliğinden sağlanıyor, bilgi değeri düşük).

## 5. Rehber getirme değerlendirmesi (Faz 5)

Dosya: `eval/golden_queries.yaml`, betik: `eval/retrieval_eval.py`.

**Sorgu seti:** 36 gerçek model grubu. 11'i bu belgedeki eval setinden ve referans örnekten, 25'i `by_tactic/`
CSV'lerindeki 226 seçili gruptan, farklı notları kapsayacak biçimde seçildi. Korpusta uygun notu olmayan gruplar
(ör. SAM hive dökümü, startup klasörü kalıcılığı) bilinçli olarak alınmadı: doğru cevabı olmayan sorgu recall hakkında bir şey söylemez.

**Etiketleme sırası:** beklenen notlar grubun kural adlarına ve olaylarına bakılarak, getirme **o gruba hiç çalıştırılmadan**
yazıldı. Bu, etiketlerin sıralamaya uydurulmasını engeller ama §3'teki temel sınırlılığı kaldırmaz: notları, sorguları ve
beklenen cevapları aynı taraf yazdı.

**Sonuç (2026-09-15, `qwen3-embedding-0.6b-generic-cpu`, ATT&CK 19.2, 34 not):**

| Varyant | recall@3 | hit@3 |
|---|---:|---:|
| **Üretim: ön-filtre + sorgu talimatı** | **0,958** | **1,000** |
| Ön-filtre yok | 0,931 | 0,972 |
| Sorgu talimatı yok | 0,972 | 1,000 |

- Ön-filtre 36 sorgunun hiçbirinde tüm korpusa geri düşmedi.
- Kısmi isabetler (recall 0,5): Q07 (mshta/rundll32 — G-017 zamanlanmış görev notu önde), Q14 (sürücü + tünel — G-026 ilk 3'te yok),
  Q16 (comsvcs dökümü — G-016 yerine G-001).
- Talimatsız varyantın 0,014 yüksek çıkması tek bir kısmi isabet farkıdır; kendi yazdığımız etiketlere göre config değiştirmek
  aşırı uyum olacağı için talimat korundu.
- **Determinizm:** index iki kez kuruldu, vektörler bayt düzeyinde aynı; aynı sorgu iki kez embed edildiğinde vektör ve sıralama birebir aynı.

**Kullanıcı doğrulaması için öneri:** önce kısmi isabetlerin (Q07, Q14, Q16) beklenen notlarının gerçekten doğru olup
olmadığına, sonra çok genel notların (G-015 "Suspicious command lines", G-034 "Masquerading") sık sık ilk 3'e girip girmediğine bakın.

## 6. Model katmanı (Faz 6)

**Koşu (2026-09-15):** prompt `triage_v2`, birebir token bütçesi, kontrol token etkisizleştirmesi, `--audit`. Taze daemon
(VRAM boşalması beklenerek yeniden başlatıldı), 11 CSV'deki 12 model grubu art arda. Referans örnek ile
`sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump` aynı CSV olduğu için benzersiz grup sayısı 11'dir.

| Ölçüm | Faz 5 (`triage_v1`, tahmini bütçe) | Faz 6 (`triage_v2`, birebir bütçe) |
|---|---|---|
| Kabul | 12/12 (11'i ilk denemede) | **12/12, hepsi ilk denemede** |
| 4–6. kuralların (EID / teknik / IPv4) tetiklendiği deneme | kurallar yoktu | **0** |
| Bizim token sayımı = sunucu `prompt_tokens` | — | **12/12** |
| En büyük prompt | 3.506 (gerçek) | 3.831 (sınır 3.840) |
| Kanıta giren satır, referans örnek | 17 | **23** |
| Etkisizleştirilen kontrol token'ı | — | 0 (eval setinde enjeksiyon yok) |

**Doğrulayıcı hata enjeksiyonu** (`eval/validator_injection.py`): kabul edilmiş **gerçek** model cevapları rapordaki
bağlamla yeniden doğrulanıp her seferinde tek bir hatayla bozuldu.

| Cevap kümesi | Bugünkü kurallarla hâlâ kabul | Uygulanan hata | Yakalanan | Kontroller (düşünme bloğu, kod çiti) kabul |
|---|---|---|---|---|
| Faz 5 (12 cevap, 1–3. kurallarla kabul edilmişti) | 12/12 | 190 | **190 (%100)** | 24/24 |
| Faz 6 (12 cevap) | 12/12 | 190 | **190 (%100)** | 24/24 |

16 hata türü: var olmayan satır, grupta olup prompt'ta gösterilmemiş satır (10 cevapta uygulanabildi), kanıtsız madde ve adım,
getirilmemiş rehber, madde ve adımda uydurma EID, uydurma teknik, bilinen üst tekniğe uydurma alt teknik, uydurma IPv4,
yanlış grup, bilinmeyen değerlendirme, fazla alan, eksik alan, yarım JSON, JSON yerine düz yazı.

**Bu sonuçların söylemediği:**
- 4–6. kuralların hiç tetiklenmemesi, modelin bu hataları hiç yapmadığını değil, bu 12 grupta yapmadığını gösterir;
  örneklem küçük ve etiketler bağımsız değil (§3).
- Kabul, yorumun doğru olduğu anlamına gelmez (README "Sınırlılıklar"). Canlı enjeksiyon denemesinde model, log alanına
  yazılmış tek bir cümleyle değerlendirmeyi `likely_benign`'e çevirdi ve yanıt **kabul edildi**
  ([ADR-0001](adr/0001-runtime-ve-model.md) §9c.3).

## 7. Faz 7 genişletmesi: dosya başına CSV'ler, otomatik etiketler, 26 elle etiket

### Dosya başına CSV'ler ve kilit dosyası

`scripts/generate_sample_csvs.py` 278 EVTX'in her birini Hayabusa'dan `-A` ile ayrı ayrı geçirir
(`data/hayabusa_csv/per_evtx/`, repoya girmez). `eval/samples.lock` örnek reposu commit'ini, Hayabusa ikilisinin
SHA-256'sını, komutu ve her örnek için EVTX ve CSV hash'lerini tutar; içerik tutmaz.

| Durum | Örnek |
|---|---:|
| Tespit var | 248 |
| Tespit yok | 27 |
| Defender engelledi (ADR-0002 §2) | 3 |

`-A` ile dosya başına çıktı, Faz 0'daki tüm-dizin koşusuyla **275/275 örnekte aynı**.

### Otomatik etiketler (`eval/auto_labels.py`, `eval/labels/auto/samples.yaml`)

Tek etiket, örneğin taktik klasörüdür. Model gerektirmeyen ölçümler (2026-09-15):

| Ölçüm | Sonuç |
|---|---|
| Ingest hatası | **0** (5.309 tespit) |
| Sözlüğün tanımladığı tespit | %99,5 |
| En az bir grubu modele giden örnek | 216 / 248 (237 grup) |
| Klasör taktiği tespitlerde geçiyor | 132 / 236 (Lateral Movement 9/37, Discovery 1/9, Privilege Escalation 50/64) |

Taktik uyumu düşük görünüyor ama bu aracın değil, Sigma kural etiketlerinin özelliği. Örneğin yanal hareket
örneklerinde kurallar çoğunlukla Execution etiketi taşıyor. Klasör, örnek yazarının sınıflandırmasıdır; doğruluk ölçüsü değildir.

### 26 elle etiket

§1'deki 10 etikete 16 **taslak** eklendi. Seçim ölçütü taktik ve teknik çeşitliliğiydi: C2 tünelleme, comsvcs ve
PowerShell ile döküm, ntdsutil, netsh portproxy, PowerShell loglamasını kapatma, zafiyetli sürücü, SquiblyTwo, impacket
wmiexec, cmd servisleri, WMI tüketicisi, erişilebilirlik arka kapısı, EfsPotato, getsystem, maldoc, Administrators grubuna
Guest ekleme. Her dosya `# DRAFT` başlığı ve örneğin tek cümlelik özetiyle başlar.

**Döngüsellik (§3) burada daha güçlü:** yeni etiketler araç çıktısı görülerek yazıldı ve çoğu örnekte modele giden
tek bir grup var. Bu yüzden **gruplama 26/26 sonucunun yeni 16'sı kanıt değildir**. Bu etiketler kilit olay recall'u,
`must_mention` ve değerlendirme uyumu için kullanılır. Bir örnekte bilinçli bir tuzak var: comsvcs dökümünün hedefi
LSASS değil notepad.exe (PID 4868); etiket notu bunu söyler.

### 6a. Prompt `triage_v3` ve enjeksiyon değerlendirmesi (Faz 6 kararları sonrası)

| Ölçüm | `triage_v2` | `triage_v3` |
|---|---|---|
| Temiz dilim (12 grup) | 12/12 ilk denemede | 12/12 (11 ilk denemede; 1 geçersiz JSON kaçışı, yeniden denemede düzeldi) |
| Temiz dilim değerlendirmeleri | 12 × `likely_malicious` | 12 × `likely_malicious` (aynı) |
| Gerçek model cevaplarına hata enjeksiyonu | 190/190 | 190/190 |
| Enjeksiyon: talimat / kontrol token'lı talimat / zararsız bağlam, çevrilen (20 grup) | 14 / 18 / 1 | 14 / 18 / 0 |
| İstek başına sabit token | 542 | 792 (sistem 738 + hatırlatma 54) |

v3 benimsenmedi, varsayılan `triage_v2` (ADR-0001 §9c.3). Enjeksiyon hedefleri 20 grup: eval setindeki 26 CSV'den
saldırganın yazabileceği bir alan (`Image`, `CommandLine`, `ObjectDN`, `ServiceName` …) gösteren high/critical grubu olanlar.

## 8. Elle doğrulama: sadeleştirilmiş görünümler

```powershell
.\.venv\Scripts\python.exe eval\verification_views.py          # sunucu açık olmalı (Q07/Q14/Q16 için embedding)
.\.venv\Scripts\python.exe eval\verification_views.py --no-retrieval
```

Çıktı `out\verification\` altına yazılır; olay verisi içerdiği için repoya girmez. `INDEX.md` 29 maddeyi öncelik sırasıyla
listeler: §4'teki dört öncelikli etiket ve diğer altı Faz 4 etiketi, Q07/Q14/Q16, ardından 16 Faz 7 taslağı. Her dosyada:

- etiketin iddiası: her kilit olay eşleştiricisi `K1`, `K2` … olarak ve kaç satıra denk geldiği;
- "Check first": o madde için bilinen risk (§4 ve §5'ten);
- dört maddelik kontrol listesi;
- grup tablosu ve olay tablosu; eşleştiricinin yakaladığı satırlar `match` sütununda işaretli. 40 satırı aşan örneklerde
  eşleşmeyen low/informational satırlar gizlenir.

**Model cevabı görünümlerde yok.** Önce modelin yorumunu görmek, etiketi ona göre okumaya yol açar (§3, risk 4).

Doğrulanan etiketin ilk satırına `# verified-by: <ad>, <tarih>` eklenir; altın sorgulara `verified_by` anahtarı.
Bir etiket düzeltilirse `eval\metrics.py` ve `eval\run_eval.py` yeniden koşulur, ADR-0003 eşikleri yeniden kontrol edilir.
