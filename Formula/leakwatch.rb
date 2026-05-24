# Homebrew formula for Leakwatch
# Install: brew install HodeTech/tap/leakwatch
class Leakwatch < Formula
  desc "High-performance secret scanner for codebases, Git histories, and container images"
  homepage "https://github.com/HodeTech/Leakwatch"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/HodeTech/Leakwatch/releases/latest/download/leakwatch_Darwin_arm64.tar.gz"
    end
    on_intel do
      url "https://github.com/HodeTech/Leakwatch/releases/latest/download/leakwatch_Darwin_amd64.tar.gz"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/HodeTech/Leakwatch/releases/latest/download/leakwatch_Linux_arm64.tar.gz"
    end
    on_intel do
      url "https://github.com/HodeTech/Leakwatch/releases/latest/download/leakwatch_Linux_amd64.tar.gz"
    end
  end

  def install
    bin.install "leakwatch"
  end

  test do
    assert_match "leakwatch", shell_output("#{bin}/leakwatch version")
  end
end
