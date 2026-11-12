---
title: "Kurulum"
description: "Leakwatch'ı Homebrew, go install, Docker veya hazır bir ikili dosya ile kurun."
---

# Kurulum

Leakwatch'ı makinenize kurmak bir dakikadan az sürer. İş akışınıza en uygun yöntemi seçin: Homebrew macOS ve Linux'ta en basit seçenektir, `go install` halihazırda bir Go araç zinciriniz varsa idealdir, Docker ana sisteminizi temiz tutar ve hazır ikili dosyalar herhangi bir araç zinciri gerektirmeden her yerde çalışır.

## Homebrew (macOS ve Linux)

Resmi tap, amd64 ve arm64 mimarilerinde macOS ve Linux'u destekler.

```bash
brew install HodeTech/tap/leakwatch
```

Tap, [github.com/HodeTech/homebrew-tap](https://github.com/HodeTech/homebrew-tap) adresinde barındırılmaktadır. Homebrew ile yükseltmek için `brew upgrade leakwatch` komutunu kullanın.

## go install

Go 1.27.4 veya daha yeni bir sürümü yüklüyse, en son sürümü doğrudan kaynaktan derleyip kurabilirsiniz:

```bash
go install github.com/HodeTech/leakwatch@latest
```

İkili dosya `$(go env GOPATH)/bin` dizinine yerleştirilir. Bu dizinin `PATH` değişkeninde olduğundan emin olun.

:::note
`go install` her zaman en son etiketli sürümü getirir. Belirli bir sürüme sabitlemek için `@latest` yerine güncel sürüm etiketi olan `@v1.8.2` değerini kullanın.
:::

## Docker

Minimal, çok aşamalı bir Alpine imajı GitHub Container Registry'de yayımlanmaktadır. İmaj, root olmayan bir kullanıcı (`leakwatch`) olarak çalışır, CGO devre dışıdır ve çalışma dizini olarak `/scan` kullanır.

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan
```

Kullanılabilir etiketler:

| Etiket | Açıklama |
|--------|----------|
| `:latest` | En son sürüm |
| `:1.8.2` | Güncel sürüme tam sabitleme |
| `:v1.8` | Güncel küçük sürüme sabitleme (yama sürümlerini takip eder) |

Taramak istediğiniz dizini konteyner içindeki `/scan` dizinine bağlayın. Bayraklar ve seçenekler yerel ikili dosyayla tamamen aynı şekilde çalışır — tam liste için [CLI Referansı](#/reference/cli-reference) sayfasına bakın.

:::tip
Uzak Git depolarını tarama ve kimlik bilgilerini güvenli biçimde geçirme dahil Docker'a özgü kullanım kalıpları için [Docker Kullanımı](#/ci-cd/docker-usage) sayfasına bakın.
:::

### İmaj imzasını doğrulama

Sürüm imajları [Sigstore/cosign](https://github.com/sigstore/cosign) ile anahtarsız imzalanır. v1.8.3 ve sonrasında imza; `:latest`, tam sürüm etiketi ve küçük sürüm etiketinin hepsinin çözümlendiği çok mimarili manifest listesini kapsar; böylece gerçekten çektiğiniz referansı doğrulayabilirsiniz:

```bash
cosign verify ghcr.io/hodetech/leakwatch:latest \
  --certificate-identity-regexp '^https://github\.com/HodeTech/Leakwatch/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

v1.8.2 dahil önceki sürümlerde yalnızca mimariye özgü imajlar imzalanmıştı; bu sürümler için bunun yerine `:<sürüm>-amd64` veya `:<sürüm>-arm64` etiketini doğrulayın (örneğin `:1.8.2-amd64`).

## Hazır ikili dosya

Her sürüm, desteklenen tüm platformlar için [GitHub Releases](https://github.com/HodeTech/Leakwatch/releases) sayfasında arşivler yayımlar. Platformunuza ait arşivi indirin, doğrulayın, açın ve ikili dosyayı `PATH` değişkeninizdeki bir dizine taşıyın.

**Desteklenen platformlar:** amd64 ve arm64 mimarilerinde Linux, macOS ve Windows.

Arşiv adları `leakwatch_<SÜRÜM>_<OS>_<ARCH>.tar.gz` kalıbını izler (Windows'ta `.zip`); `<SÜRÜM>` başında `v` olmadan yazılır (örneğin `1.8.2`), `<OS>` değeri `linux`, `darwin` veya `windows`, `<ARCH>` değeri ise `amd64` veya `arm64` olabilir. Sürüm varlıklarının adında her zaman sürüm numarası bulunur; bu yüzden `latest/download/...` biçimli bir URL'de de güncel sürümü açıkça yazmanız gerekir. Aşağıdaki komutlar sürümü açıkça sabitler.

Aşağıdaki üç adım kabuk değişkenlerini paylaşır; bu yüzden aynı terminal oturumunda çalıştırın.

### 1. İndirme

`OS` ve `ARCH` değerlerini platformunuza göre ayarlayın (örnek Linux amd64'tür):

```bash
LEAKWATCH_VERSION=v1.8.2
OS=linux      # linux veya darwin (Windows .zip arşivi kullanır: Releases sayfasından indirin)
ARCH=amd64    # amd64 veya arm64
ARCHIVE="leakwatch_${LEAKWATCH_VERSION#v}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/HodeTech/Leakwatch/releases/download/${LEAKWATCH_VERSION}"
curl -LO "${BASE_URL}/${ARCHIVE}"
```

### 2. Doğrulama (önerilir)

Her sürüm ayrıca her arşiv için bir Yazılım Malzeme Listesi (SBOM, `<arşiv>.sbom.json`), bir `checksums.txt` dosyası ve bu sağlama toplamları dosyası üzerinde bir [Sigstore/cosign](https://github.com/sigstore/cosign) anahtarsız imza paketi (`checksums.txt.bundle`) yayımlar. Tedarik zinciri açısından hassas ortamlarda, herhangi bir şeyi açmadan veya çalıştırmadan **önce** `checksums.txt` imzasını doğrulayın, ardından arşivinizi bu dosyaya göre kontrol edin. Her komut yalnızca bir öncekinin başarılı olması durumunda çalışır; böylece başarısız bir imza denetimi diziyi durdurur:

```bash
curl -LO "${BASE_URL}/checksums.txt" && \
curl -LO "${BASE_URL}/checksums.txt.bundle" && \
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp '^https://github\.com/HodeTech/Leakwatch/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt && \
grep " ${ARCHIVE}\$" checksums.txt | sha256sum --check
```

macOS'ta `sha256sum --check` yerine `shasum -a 256 --check` kullanın. Eksik veya uyuşmayan bir sağlama toplamı kaydı, son komutun sıfırdan farklı bir kodla çıkmasına neden olur.

### 3. Kurulum

```bash
tar -xzf "${ARCHIVE}"
sudo mv leakwatch /usr/local/bin/leakwatch
```

## Kurulumu doğrulama

Herhangi bir kurulum yönteminin ardından ikili dosyanın erişilebilir olduğunu doğrulayın ve sürümü kontrol edin:

```bash
leakwatch version
```

Beklenen çıktı:

```text
leakwatch 1.8.2 (commit: 1a2b3c4, built: 2026-11-12T12:00:00Z)
```

Komut bulunamazsa kurulum dizininin `PATH` değişkeninde olup olmadığını kontrol edin.

## Sonraki adımlar

- [Hızlı Başlangıç](#/getting-started/quick-start) — ilk taramanızı bir dakikadan kısa sürede çalıştırın.
- [Nasıl Çalışır](#/getting-started/how-it-works) — Leakwatch taramasının arkasındaki mimari.
- [Yapılandırma Dosyası](#/configuration/config-file) — `.leakwatch.yaml` ile tarama davranışını özelleştirin.

## Ayrıca bakın

- [Hızlı Başlangıç](#/getting-started/quick-start)
- [Docker Kullanımı](#/ci-cd/docker-usage)
- [CLI Referansı](#/reference/cli-reference)
- [Yapılandırma Dosyası](#/configuration/config-file)
