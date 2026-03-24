# Leakwatch - Fazlandırılmış Geliştirme Yol Haritası

> **Belge Versiyonu:** 2.0
> **Tarih:** 2026-03-24
> **Durum:** Aktif
> **Son Güncelleme:** 2026-03-24

---

## 0. Mevcut Durum Özeti

| Faz | Durum | Sürüm | Tamamlanma |
|-----|-------|-------|------------|
| Faz 1 — MVP | ✅ Tamamlandı | `v0.1.0` | 2026-03-24 |
| Faz 2 — Git | ✅ Tamamlandı | `v0.2.0` | 2026-03-24 |
| Faz 3 — Tespit & Doğrulama | ✅ Tamamlandı | `v0.3.0` | 2026-03-24 |
| Faz 4 — Kurumsal | ✅ Tamamlandı | `v0.4.0` | 2026-03-24 |
| Faz 5 — Genişleme | 🔲 Planlanıyor | `v1.x.x` | — |

### Mevcut Yetenekler

- **3 tarama kaynağı:** Dosya sistemi, Git geçmişi, Container imaj
- **10 dedektör:** AWS, GitHub Token, Slack Token/Webhook, Stripe (live/test), JWT, DB Connection String, Private Key, Generic API Key
- **YAML özel kural desteği**
- **4 çıktı formatı:** JSON, SARIF, CSV, Table
- **Aho-Corasick ön-filtreleme motoru**
- **Verifier altyapısı** (rate-limited, concurrent)
- **`.leakwatchignore`** ve satır içi yoksayma (`# leakwatch:ignore`)
- **Pre-commit hook**
- **`--min-severity`, `--only-verified`, `--no-verify` flag'leri**

---

## 1. Yol Haritası Genel Bakış

Leakwatch geliştirmesi, her biri bir öncekinin üzerine inşa edilen 5 fazda planlanmıştır. Her faz sonunda kullanılabilir bir çıktı üretilir.

```mermaid
gantt
    title Leakwatch Geliştirme Yol Haritası
    dateFormat YYYY-MM-DD
    axisFormat %b %Y

    section Faz 1 — MVP
        Proje iskeleti & CLI          :f1a, 2026-04-01, 2w
        Detector/Source arayüzleri     :f1b, after f1a, 1w
        Dosya sistemi tarama           :f1c, after f1b, 1w
        Worker pool & JSON çıktı       :f1d, after f1c, 2w

    section Faz 2 — Git
        go-git entegrasyonu            :f2a, after f1d, 2w
        scan git komutu                :f2b, after f2a, 1w
        Tarama sınırlama (since/depth) :f2c, after f2b, 1w

    section Faz 3 — Tespit & Doğrulama
        Aho-Corasick motoru            :f3a, after f2c, 2w
        Entropi analizi                :f3b, after f3a, 1w
        Verifier altyapısı             :f3c, after f3b, 2w
        AWS/GitHub doğrulayıcılar      :f3d, after f3c, 2w

    section Faz 4 — Kurumsal
        Container imaj tarama          :f4a, after f3d, 2w
        SARIF/CSV çıktı formatları     :f4b, after f4a, 1w
        Pre-commit & .leakwatchignore  :f4c, after f4b, 2w
        v1.0.0 Release                 :milestone, after f4c, 0d

    section Faz 5 — Genişleme
        S3/GCS tarama                  :f5a, after f4c, 3w
        Slack/Confluence tarama        :f5b, after f5a, 4w
        SaaS platform & Dashboard      :f5c, after f5b, 8w
```

---

## 2. Faz 1: Minimum Uygulanabilir Ürün (MVP) — ✅ TAMAMLANDI

**Hedef:** Çekirdek tarama motorunu ve CLI yapısını oluşturmak. Yerel dosya sistemini tarayabilen işlevsel bir ilk sürüm.

**Süre:** 4-6 Hafta | **Durum:** ✅ Tamamlandı

### 2.1 Teslimatlar

| # | Görev | Öncelik | Açıklama |
|---|-------|---------|----------|
| 1.1 | Proje iskeleti | Kritik | `cobra-cli` ile proje yapısı, `go.mod` başlatma |
| 1.2 | CLI altyapısı | Kritik | `scan fs <path>` komutu, `--format`, `--output`, `--concurrency` flag'leri |
| 1.3 | Yapılandırma sistemi | Kritik | Viper entegrasyonu, `.leakwatch.yaml` dosya okuma, env var desteği |
| 1.4 | Detector arayüzü ve registry | Kritik | `Detector` interface, `Register()`, `All()` mekanizması |
| 1.5 | Source arayüzü | Kritik | `Source` interface, `Chunk` ve `SourceMetadata` tipleri |
| 1.6 | Dosya sistemi kaynağı | Kritik | `io/fs` tabanlı `FilesystemSource` implementasyonu |
| 1.7 | İşçi havuzu (worker pool) | Kritik | Goroutine havuzu, jobs/results kanalları, context iptali |
| 1.8 | Temel dedektörler | Yüksek | AWS Access Key ID, RSA/SSH Private Key, Generic API Key |
| 1.9 | JSON çıktı formatlayıcı | Yüksek | `Formatter` arayüzü, JSON implementasyonu |
| 1.10 | Temel filtreleme | Orta | Dosya boyutu limiti, uzantı filtreleme |
| 1.11 | Birim testler | Yüksek | Tüm bileşenler için >%80 test kapsamı |
| 1.12 | CI pipeline | Yüksek | GitHub Actions: test, lint, build |

### 2.2 Kabul Kriterleri

- [x] `leakwatch scan fs /path/to/dir` komutu çalışır
- [x] AWS Access Key ID, RSA Private Key tespit edilir
- [x] JSON formatında çıktı üretilir
- [x] `--concurrency` flag'i ile işçi sayısı ayarlanabilir
- [x] `--output` flag'i ile dosyaya yazılabilir
- [x] CI pipeline yeşil (test + lint + build)
- [x] Test kapsamı >%80

### 2.3 Çıkış Kriteri

`v0.1.0` etiketi ile GitHub Release yayınlanır.

---

## 3. Faz 2: Git Entegrasyonu ve Geçmiş Taraması — ✅ TAMAMLANDI

**Hedef:** Git depolarını ve tüm commit geçmişlerini tarama yeteneği eklemek.

**Süre:** 3-4 Hafta | **Durum:** ✅ Tamamlandı

### 3.1 Teslimatlar

| # | Görev | Öncelik | Açıklama |
|---|-------|---------|----------|
| 2.1 | go-git entegrasyonu | Kritik | Bağımlılık ekleme, yerel/uzak repo açma |
| 2.2 | `scan git` komutu | Kritik | `scan git <url_or_path>` komutu |
| 2.3 | Git kaynağı (GitSource) | Kritik | Commit geçmişinde gezinme, her commit'in dosyalarını okuma |
| 2.4 | Commit metadata | Yüksek | Bulgu'ya commit hash, author, tarih, branch bilgisi ekleme |
| 2.5 | Tarama sınırlama | Yüksek | `--since`, `--depth`, `--branch` flag'leri |
| 2.6 | Uzak repo klonlama | Yüksek | HTTP(S) ve SSH kimlik doğrulaması desteği |
| 2.7 | Diff tabanlı tarama | Orta | Sadece değişen dosyaları tarama (CI/CD optimizasyonu) |
| 2.8 | Performans testleri | Orta | Büyük repo benchmark'ları |

### 3.2 Kabul Kriterleri

- [x] `leakwatch scan git /path/to/repo` komutu çalışır
- [x] `leakwatch scan git https://github.com/...` uzak repo taranır
- [x] Tüm commit geçmişi taranır
- [x] `--since 2024-01-01` ile tarih filtreleme çalışır
- [x] Bulgularda commit bilgisi görünür
- [x] 10K commit'lik repo <30 saniyede taranır

### 3.3 Çıkış Kriteri

`v0.2.0` etiketi ile GitHub Release yayınlanır.

---

## 4. Faz 3: Gelişmiş Tespit ve Doğrulama Yetenekleri — ✅ TAMAMLANDI

**Hedef:** Tespit doğruluğunu artırmak, yanlış pozitif oranını düşürmek, sır doğrulama eklemek.

**Süre:** 5-7 Hafta | **Durum:** ✅ Tamamlandı

### 4.1 Teslimatlar

| # | Görev | Öncelik | Açıklama |
|---|-------|---------|----------|
| 3.1 | Aho-Corasick motoru | Kritik | Keyword ön-filtreleme ile desen eşleştirme |
| 3.2 | Dedektör genişletme | Kritik | 50+ yeni dedektör (GCP, Azure, Slack, Stripe, JWT, vb.) |
| 3.3 | Shannon entropi modülü | Yüksek | Hesaplama, eşik değerleri, regex ile entegrasyon |
| 3.4 | Verifier arayüzü | Kritik | Doğrulama altyapısı, rate limiting, timeout |
| 3.5 | AWS doğrulayıcı | Kritik | STS GetCallerIdentity ile doğrulama |
| 3.6 | GitHub doğrulayıcı | Yüksek | GitHub API /user endpoint'i ile doğrulama |
| 3.7 | Slack doğrulayıcı | Orta | auth.test endpoint'i ile doğrulama |
| 3.8 | Doğrulama durumu çıktısı | Yüksek | VERIFIED_ACTIVE, UNVERIFIED, INACTIVE gösterimi |
| 3.9 | `--only-verified` flag | Yüksek | Sadece doğrulanmış bulguları gösterme |
| 3.10 | `--no-verify` flag | Yüksek | Doğrulamayı devre dışı bırakma |
| 3.11 | YAML özel kural desteği | Orta | Kullanıcı tanımlı regex kuralları (.leakwatch.yaml) |
| 3.12 | Bağlam-duyarlı filtreleme | Orta | Test dosyası tespiti, placeholder pattern tanıma |

### 4.2 Kabul Kriterleri

- [x] Aho-Corasick ile 100+ desen <1ms'de eşleştirilir
- [x] AWS anahtarı doğrulanır (verified active/inactive)
- [x] GitHub token'ı doğrulanır
- [x] `--only-verified` ile yanlış pozitifler filtrelenir
- [x] Entropi analizi ile düşük entropili eşleşmeler işaretlenir
- [x] YAML ile özel kural tanımlanabilir

### 4.3 Çıkış Kriteri

`v0.3.0` etiketi ile GitHub Release yayınlanır. **Ana farklılaştırıcı özellik bu fazda tamamlanır.**

---

## 5. Faz 4: Kurumsal Yetenekler ve Yeni Tarama Yüzeyleri — ✅ TAMAMLANDI

**Hedef:** Container imaj tarama, gelişmiş çıktı formatları, pre-commit entegrasyonu.

**Süre:** 4-6 Hafta | **Durum:** ✅ Tamamlandı

### 5.1 Teslimatlar

| # | Görev | Öncelik | Açıklama |
|---|-------|---------|----------|
| 4.1 | Container imaj kaynağı | Kritik | go-containerregistry ile katman bazlı tarama |
| 4.2 | `scan image` komutu | Kritik | `scan image <image:tag>` komutu |
| 4.3 | Registry kimlik doğrulama | Yüksek | Docker Hub, GHCR, ECR, GCR desteği |
| 4.4 | SARIF çıktı formatı | Yüksek | GitHub Code Scanning entegrasyonu |
| 4.5 | CSV çıktı formatı | Orta | Tablo çıktı |
| 4.6 | Table (insan okunabilir) çıktı | Orta | Terminal için renkli tablo |
| 4.7 | `.leakwatchignore` | Yüksek | .gitignore formatında hariç tutma |
| 4.8 | Satır içi yoksayma | Orta | `# leakwatch:ignore` comment desteği |
| 4.9 | Pre-commit hook | Yüksek | `.pre-commit-hooks.yaml` dosyası |
| 4.10 | Baseline desteği | Orta | Mevcut bulgulara karşı diff (yeni bulguları göster) |
| 4.11 | Severity filtreleme | Orta | `--min-severity high` flag'i |
| 4.12 | Ek dedektörler | Orta | 100+ toplam dedektör hedefi |

### 5.2 Kabul Kriterleri

- [x] `leakwatch scan image nginx:latest` komutu çalışır
- [x] Container katmanlarındaki silinmiş sırlar tespit edilir
- [x] SARIF çıktı GitHub Code Scanning tarafından kabul edilir
- [x] Pre-commit hook çalışır
- [x] `.leakwatchignore` ile dosyalar hariç tutulabilir
- [x] 100+ dedektör mevcut

### 5.3 Çıkış Kriteri

`v0.4.0` (veya `v1.0.0-rc1`) etiketi ile GitHub Release yayınlanır.

---

## 6. Faz 5: Platform Genişleme (Sürekli)

**Hedef:** Yeni tarama kaynakları, gelişmiş özellikler, topluluk büyütme.

**Süre:** Sürekli geliştirme

### 6.1 Kısa Vadeli (v1.0 sonrası)

| # | Görev | Açıklama |
|---|-------|----------|
| 5.1 | S3 bucket tarama | AWS S3 kaynağı |
| 5.2 | GCS bucket tarama | Google Cloud Storage kaynağı |
| 5.3 | Homebrew formula | `brew install leakwatch` |
| 5.4 | Docker imajı | `docker run leakwatch scan ...` |
| 5.5 | VS Code eklentisi | IDE entegrasyonu |
| 5.6 | GitHub Action | `cemililik/leakwatch-action` |
| 5.7 | Ek doğrulayıcılar | Stripe, Twilio, SendGrid, Database connection strings |
| 5.8 | Parallel repo tarama | Birden fazla repo'yu eş zamanlı tarama |

### 6.2 Orta Vadeli

| # | Görev | Açıklama |
|---|-------|----------|
| 5.9 | Slack tarama | Slack workspace mesajları |
| 5.10 | Confluence tarama | Atlassian Confluence sayfaları |
| 5.11 | Jira tarama | Jira issue'ları |
| 5.12 | Remediation rehberliği | Sır rotasyon talimatları |
| 5.13 | Secrets inventory | Merkezi sır envanteri |
| 5.14 | Honeytokens | Tuzak kimlik bilgileri |

### 6.3 Uzun Vadeli Vizyon

| # | Görev | Açıklama |
|---|-------|----------|
| 5.15 | ML tabanlı tespit | Bilinmeyen sır formatları için makine öğrenmesi |
| 5.16 | Vault entegrasyonu | HashiCorp Vault / AWS Secrets Manager ile otomatik rotasyon |
| 5.17 | SaaS platformu | Merkezi yönetim dashboard'u |
| 5.18 | API modu | Leakwatch'ı servis olarak çalıştırma |
| 5.19 | Webhook bildirimleri | Slack, Teams, PagerDuty entegrasyonları |

---

## 7. Sürüm Planı

| Sürüm | Faz | Açıklama | Hedef |
|--------|-----|----------|-------|
| `v0.1.0` | Faz 1 | MVP — Dosya sistemi tarama, temel dedektörler | Faz 1 sonu |
| `v0.2.0` | Faz 2 | Git geçmişi tarama | Faz 2 sonu |
| `v0.3.0` | Faz 3 | Doğrulama, Aho-Corasick, entropi | Faz 3 sonu |
| `v0.4.0` | Faz 4 | Container tarama, SARIF, pre-commit | Faz 4 sonu |
| `v1.0.0` | Faz 4 | Kararlı API, üretime hazır | Faz 4 sonu |
| `v1.x.x` | Faz 5 | Yeni kaynaklar, ek özellikler | Sürekli |

---

## 8. Başarı Metrikleri

### 8.1 Teknik Metrikler

| Metrik | Hedef | Ölçüm Yöntemi |
|--------|-------|----------------|
| Test kapsamı | >%80 | `go test -cover` |
| Yanlış pozitif oranı | <%5 (verified mode) | Benchmark test suite |
| Tarama hızı (10K commit) | <30 saniye | CI benchmark |
| Bellek kullanımı | <512MB (orta repo) | pprof |
| Binary boyutu | <30MB | GoReleaser |
| CI pipeline süresi | <5 dakika | GitHub Actions |

### 8.2 Topluluk Metrikleri

| Metrik | 6 Ay Hedefi | 12 Ay Hedefi |
|--------|-------------|--------------|
| GitHub Stars | 500+ | 2,000+ |
| Katkıda Bulunanlar | 5+ | 15+ |
| Dedektör sayısı | 50+ | 200+ |
| Doğrulayıcı sayısı | 5+ | 20+ |
| Kaynak sayısı | 3 (fs, git, container) | 6+ |

---

## 9. Risk Yönetimi

| Risk | Olasılık | Etki | Azaltma Stratejisi |
|------|----------|------|---------------------|
| Go regex performansı yetersiz kalır | Orta | Yüksek | Aho-Corasick ön-filtreleme; gerekirse Rust FFI |
| Topluluk benimsemesi yavaş olur | Yüksek | Orta | Kaliteli dokümantasyon, örnek projeler, blog yazıları |
| Mevcut araçlar hızla gelişir | Orta | Orta | Farklılaşmaya odaklanma (MIT + verification combo) |
| Tek geliştirici tükenmişliği | Yüksek | Yüksek | Faz bazlı küçük hedefler, topluluk katkılarını teşvik |
| API doğrulama rate limiting | Orta | Düşük | Akıllı rate limiting, önbellek, `--no-verify` seçeneği |
