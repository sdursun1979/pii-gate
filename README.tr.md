# pii-gate

**Yapay zeka kodlama ajanları için kapalı başarısız olan kişisel veri kapısı.**

Codex CLI ve Claude Code'a kurulan tek bir kanca. Ajan bir kabuk komutu çalıştırmadan, dosya yazmadan,
internete çıkmadan ya da siz bir istem göndermeden **önce** içeriğe bakar; kişisel veri ya da gizli
anahtar sızdıracaksa durdurur.

Ajanların kendi izin sistemi *aracı* tanır, *veriyi* tanımaz: `curl` bir paket indirirken de, bir hasta
listesini dışarı gönderirken de aynı `curl`'dür. KVKK ortamında o tek komut bildirim gerektiren bir
ihlaldir. pii-gate çağrının içeriğini okur ve gerektiğinde hayır der.

## Kurulum

```
pip install pii-gate
pii-gate install codex      # ~/.codex/hooks.json
pii-gate install claude     # ~/.claude/settings.json
pii-gate status
```

Codex yalnız güvendiğiniz kancaları çalıştırır: `codex` içinde `/hooks` yazıp yeni kaydı onaylayın.
Tek bir depoya kurmak için `--project` ekleyin. Python 3.9 ve üstü, bağımlılık yok.

## Ne engeller

| kural             | varsayılan | ne                                                                        |
|-------------------|------------|---------------------------------------------------------------------------|
| `tckn`            | engel      | TC kimlik numarası (iki kontrol basamağı doğrulanır)                      |
| `es-dni`          | engel      | İspanya DNI ve NIE (kontrol harfi doğrulanır)                             |
| `it-cf`           | engel      | İtalya codice fiscale (kontrol karakteri ve doğum günü doğrulanır)        |
| `nl-bsn`          | engel      | Hollanda BSN (11 kontrolü), yalnız `BSN` etiketinin yanında               |
| `pl-pesel`        | engel      | Polonya PESEL (sağlama ve doğum tarihi), yalnız `PESEL` etiketinin yanında |
| `se-personnummer` | engel      | İsveç personnummer / samordningsnummer (Luhn ve doğum tarihi), yalnız `personnummer` veya `samordningsnummer` etiketinin yanında |
| `iban`            | engel      | IBAN (mod-97 ve ülke uzunluğu)                                            |
| `card`            | engel      | Kart numarası (Luhn)                                                      |
| `secret`          | engel      | Özel anahtar, AWS, OpenAI, GitHub, Slack, Google anahtarları, JWT          |
| `exfil`           | engel      | Yükleme komutları (`curl -d`, `scp`, `rsync`, `nc`'ye boru ...) ve kişisel veri taşıyan her dış çağrı |
| `git-push`        | engel      | Ajan yayınlamaz; siz push edersiniz                                       |
| `tamper`          | engel      | `.pii-gate.json` ve kanca ayarlarına yazma, `--no-verify`, `PII_GATE_*=`   |
| `sql-pii`         | engel      | SELECT listesinde hassas kolon; kişi tablosunda ad ve iletişim kolonları  |
| `sql-star`        | engel      | Kişi tablosunda `SELECT *`                                                |
| `email`, `phone`  | uyarı      | Yalnız günlüğe yazılır                                                    |
| `secret-assign`   | uyarı      | `password = "..."` biçiminde açık atama                                   |
| `sql-pii-context` | uyarı      | Kişi tablosu dışında ad ve iletişim kolonu (tedarikçi telefonu kişisel veri değildir) |

Engellendiğinde ajana neden gösterilir ama değerin kendisi asla yazılmaz; günlükte de yalnız sayılar
vardır. Hiçbir hata durumunda kapı açık kalmaz: bozuk girdi, çöken dedektör ya da okunamayan ayar,
hepsi engeldir.

## Ayar

İsteğe bağlı `.pii-gate.json` (proje kökü ya da ev dizini). Kuralların seviyesi (`block`, `warn`,
`off`), izinli değerler, izinli yollar (sentetik test verisi), şirket e-posta alanı, ek SQL kolonları
ve kişi tabloları buradan verilir. Ajan bu dosyayı düzenleyemez; her deneme `tamper` engelidir.

## Komutlar

```
pii-gate check "metin"            # bu metne ne olur
pii-gate check --command "komut"  # kabuk kurallarıyla
pii-gate scan [yol]               # dosyaları tara
pii-gate scan --staged            # git pre-commit
pii-gate install|uninstall codex|claude|all [--project]
pii-gate status
```

Ayrıntılı belge İngilizce [README.md](README.md) dosyasındadır. Lisans: MIT.
