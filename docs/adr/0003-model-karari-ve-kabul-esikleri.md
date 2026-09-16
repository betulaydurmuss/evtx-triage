# ADR-0003 — Model kararı ve v1 kabul eşikleri

- **Durum:** Kabul edildi (Faz 7, 2026-09-16).
- **Karar veren:** kullanıcı (model); eşik değerleri bu ADR'deki ölçüme göre önerildi.
- **Kaynak:** ölçüm. `eval/run_eval.py --tag qwen25-v2`, 26 etiketli örnek, qwen2.5-7b, prompt `triage_v2`.

## 1. Karar

| Öğe | Değer |
|---|---|
| Sohbet modeli | **`qwen2.5-7b-instruct-cuda-gpu`** (Foundry Local 0.10.3, CUDA EP) |
| Embedding modeli | `qwen3-embedding-0.6b-generic-cpu` (değişmedi, ADR-0001 §7) |
| Prompt | **`triage_v2`** (sha256 `45fcbf312a17…`); `triage_v3` ölçüldü, benimsenmedi (ADR-0001 §9c.3) |
| Bağlam bütçesi | giriş 4.096, çıkış 1.024, yeniden deneme payı 256 (ADR-0001 §5) |
| Model karşılaştırması | **İptal (kullanıcı kararı, 2026-09-16).** `phi-4-mini` indirilmedi, ölçülmedi. `qwen3-8b` yalnızca "vakit kalırsa" adayıydı, denenmedi |

Plandaki Faz 7 çıkış kriteri "model kararı ADR'ye yazılır" bu belgeyle karşılanır. "Karşılaştırma" kısmı
kullanıcı kararıyla kapsamdan çıktı. Bu yüzden **qwen2.5-7b'nin alternatiflerden iyi olduğu iddia edilmez**; yalnızca
aşağıdaki eşikleri karşıladığı ölçüldü.

## 2. Temel ölçüm

**Koşullar:** 26 etiket (10'u Faz 4, 16'sı Faz 7 taslağı; bkz. `docs/eval-dataset.md` §3 ve §7), 27 model grubu.
Config hash `f23a948ae999` (ısınma anahtarı eklenmeden önceki config), sıcaklık 0, sabit seed. 19 örnek tek koşuda
geçti. 7 örnek ilk koşuda GPU OOM verdi (ADR-0001 §6, 2026-09-16 eki); sunucu yeniden başlatılıp tam bütçe ısınma
isteğinden sonra yeniden koşuldu ve geçti. Model çıktısı sıcaklık 0'da istek sırasına bağlı değil, ama OOM'lar
ısınma olmadan bu donanımda **gerçek bir risk** olarak kayda geçti.

| Metrik | Sonuç |
|---|---|
| İlk denemede kabul | **27/27** |
| İlk denemede şema-geçerli | 27/27 |
| Doğrulama öncesi uydurma (satır, not, EID, teknik, IP) | **0/27** |
| Fallback (red ya da atlama) | **0/27** (ısınmasız ilk koşuda 7/27, hepsi OOM) |
| Kilit olay recall'u, eşleştirici düzeyi | **46/53 = 0,87** |
| Kilit olay recall'u, satır düzeyi | 115/158 = 0,73 |
| `must_mention_any` isabeti | 26/26 |
| `must_not_mention` ihlali | 0 |
| Değerlendirme kabul edilebilir kümede | **23/27 = 0,85** |
| Değerlendirme uyarısı (`assessment_check`) | 3 |
| Grup başına model süresi | medyan **15,2 sn**, p90 45,4 sn, en fazla 59,8 sn |
| Prompt token'ı | medyan 2.483, en fazla 3.831 |
| Tepe GPU belleği | 7.939 / 8.188 MiB |

**Uymayanlar (okunarak):**
- Değerlendirme: 4 grupta `insufficient_evidence` (C2 tünelleme, ntdsutil, erişilebilirlik arka kapısı, RWEverything
  sürücüsü); etiketler `likely_malicious` ya da `suspicious` bekliyor. Dördü de Faz 7 taslak etiketi.
- Kilit olay: 7 eşleştirici alıntılanmadı (ör. comsvcs dökümünde 3 eşleştiricinin 1'i, WMIC/XSL'de 0/1).

**Güvenlik ölçümleri (aynı model ve prompt, ADR-0001 §9c):**
- Kontrol token enjeksiyonu etkisizleştiriliyor.
- Düz metin talimatı 20 high/critical grubun 14'ünde değerlendirmeyi çevirdi, kontrol token'lıysa 18'inde. Çelişki
  uyarısı çevrilen 32 vakanın 32'sinde çıktı.

## 3. v1 kabul eşikleri

Eşikler **etiketli sette** ve **bu donanım sınıfında** (8 GB VRAM, 14 GB RAM) ölçülür. Her eşik ölçülen değerin altında,
pay bırakılarak seçildi. Etiketler aracı yazan tarafça yazıldığı için bu değerler iyimser; **elle doğrulama borcu
kapanınca aynı betikle yeniden koşulur**, eşik tutmazsa bu ADR güncellenir.

| # | Eşik | Değer | Ölçülen | Gerekçe |
|---|---|---|---|---|
| E1 | Fallback oranı (red + atlama, ısınma açıkken) | **≤ %10** | %0 | Plandaki başlangıç önerisi korundu; OOM'lar da sayılır |
| E2 | Kilit olay recall'u, eşleştirici düzeyi | **≥ 0,75** | 0,87 | Plandaki 0,7 önerisi, ölçüm üstünde kaldığı için 0,75'e çekildi. Satır düzeyi raporlanır, eşiği yok (büyük katlanmış kümeler düşürüyor) |
| E3 | İlk denemede şema-geçerli yanıt | **≥ %90** | %100 | v3 diliminde bir JSON kaçış hatası görüldü (11/12); pay bırakıldı |
| E4 | Doğrulama öncesi uydurma | **≤ %5** | %0 | Doğrulayıcı zaten reddediyor; eşik modelin ne sıklıkla denediğini izler |
| E5 | Değerlendirme kabul edilebilir kümede | **≥ %80** | %85 | 4 `insufficient_evidence` taslak etiketlerde; doğrulamadan sonra yeniden bakılır |
| E6 | `must_mention_any` isabeti | **≥ %90** | %100 | Anahtar kelimeler gevşek (eval-dataset §3.5); tek başına kalite kanıtı değil |
| E7 | `must_not_mention` ihlali | **0** | 0 | |
| E8 | Grup başına model süresi | medyan **≤ 30 sn**, en fazla **≤ 120 sn** | 15,2 / 59,8 sn | Faz 0'da kısa promptta 9–19 sn ölçülmüştü; iki kat pay |
| E9 | GPU OOM, ısınma açıkken | **0** | 0 | Isınmanın kendisi OOM verirse koşu gruplar gönderilmeden durur; bu sayılmaz, raporlanır |
| E10 | Deterministik bölüm | aynı girdide **bayt eşit** | eşit (testler) | §11'den aynen |
| E11 | Model maddelerinin geçerli satır referansı | **%100** | %100 | Doğrulayıcının garantisi; gerçek cevaplara hata enjeksiyonu 190/190 |
| E12 | Enjeksiyonla çevrilen değerlendirmelerde uyarı (high/critical gruplar) | **%100** | 32/32 | Çevrilme oranı için eşik **yok**: önlenemediği ölçüldü, README'de sınırlılık |
| E13 | Ağ kapalıyken tam triage | **çalışır** | **karşılandı (2026-09-16)**: uçak modunda 5 kanaldan 5 örnek, 5/5 grup kabul, loopback dışı bağlantı 0 | C2 koşusu, ADR-0001 §9 |

**Ölçüm komutu** (repo kökünden, sunucu açık):

```powershell
.\.venv\Scripts\python.exe eval\run_eval.py --run --tag <etiket> --max-minutes 8 --json out\eval\run_eval_<etiket>.json
```

Bellek yüzünden koşu durursa aynı komut kaldığı yerden devam eder.

## 4. Bilinen sınırlar

- **Karşılaştırma yok.** Daha küçük bir modelin daha hızlı, daha büyüğünün daha iyi olup olmadığı bilinmiyor.
- **Tek donanım.** Yükleme sonrası GPU kullanımı koşudan koşuya 5,2–7,4 GB arasında değişti. Başka bir 8 GB kartta
  aynı bütçe tutmayabilir; `doctor` ve ısınma isteği bunu çalıştırmadan önce gösterir.
- **Etiketler bağımsız değil** (eval-dataset §3, §7). E2, E5 ve E6 doğrulamadan sonra değişebilir.
- **Düz metin enjeksiyonu önlenmiyor** (ADR-0001 §9c.3). E12 yalnızca görünürlüğü ölçer.
