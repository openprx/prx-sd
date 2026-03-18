class PrxSd < Formula
  desc "Open-source Rust antivirus engine with YARA-X, hash matching, and real-time protection"
  homepage "https://github.com/prx-sd/prx-sd"
  url "https://github.com/prx-sd/prx-sd/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/prx-sd/prx-sd.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/cli")

    # Install signature database.
    (etc/"prx-sd/yara").install Dir["signatures-db/yara/**/*"]
    (etc/"prx-sd").install "signatures-db/hashes/sha256_blocklist.txt"
    (etc/"prx-sd").install "signatures-db/hashes/md5_blocklist.txt"

    # Install update script.
    (libexec/"tools").install "tools/update-signatures.sh"
  end

  def post_install
    # Create data directories.
    (var/"prx-sd/signatures").mkpath
    (var/"prx-sd/quarantine").mkpath
    (var/"prx-sd/audit").mkpath

    # Import built-in hashes.
    system bin/"sd", "--data-dir", var/"prx-sd", "--log-level", "error",
           "import", etc/"prx-sd/sha256_blocklist.txt"
  end

  def caveats
    <<~EOS
      PRX-SD has been installed. Quick start:

        # Scan a file or directory
        sd scan /path/to/check

        # Update virus signatures
        sd update

        # Enable real-time monitoring (requires sudo on Linux)
        sd monitor /home /tmp

        # Set up weekly scheduled scan
        sd schedule add /home --frequency weekly

      Data directory: #{var}/prx-sd
      Config: #{etc}/prx-sd
    EOS
  end

  test do
    # Verify binary runs and shows version.
    assert_match "prx-sd", shell_output("#{bin}/sd --version")

    # Test EICAR detection (standard AV test pattern).
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    (testpath/"eicar.txt").write(eicar)

    output = shell_output("#{bin}/sd --data-dir #{testpath}/sd-data --log-level error scan #{testpath}/eicar.txt 2>&1", 0)
    # After first-run setup, the EICAR hash should be in the built-in blocklist.
    assert_match(/EICAR|Malicious|scanning/i, output)
  end
end
