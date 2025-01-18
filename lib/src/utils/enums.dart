/// Enumeration for AES Modes
enum AESMode {
  CBC, // Cipher Block Chaining mode
  GCM, // Galois Counter Mode
  ECB, //Electronic Codebook
}

/// Enumeration for supported AES Key Sizes
enum AESKeySize {
  AES128, // 128-bit key
  AES192, // 192-bit key
  AES256, // 256-bit key
}

extension AESKeySizeExtension on AESKeySize {
  /// Converts the AESKeySize to its corresponding bit length.
  int toBitLength() {
    switch (this) {
      case AESKeySize.AES128:
        return 128;
      case AESKeySize.AES192:
        return 192;
      case AESKeySize.AES256:
        return 256;
    }
  }

  /// Converts the AESKeySize to its corresponding byte length.
  int toByteLength() => toBitLength() ~/ 8;
}

extension AESModeExtension on AESMode {
  /// Checks if the mode requires a fixed IV size (e.g., GCM mode).
  bool requiresFixedIV() {
    return this == AESMode.GCM;
  }

  /// Provides the expected IV size for the mode.
  int ivSize() {
    if (this == AESMode.GCM) {
      return 12; // GCM standard IV size
    }
    return 16; // Default IV size for other modes
  }
}
