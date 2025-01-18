/// Centralized constants for AES encryption and decryption.
class AESConstants {
  /// Supported AES key sizes (in bits).
  static const List<int> validKeySizes = [128, 192, 256];

  /// Block size for AES (in bytes).
  static const int blockSize = 16;

  /// IV size for AES modes (in bytes).
  /// For GCM, the standard size is 12 bytes.
  static const int ivSizeGCM = 12;
  static const int ivSizeDefault = blockSize;

  /// PKCS7 padding byte size limits.
  static const int minPaddingSize = 1;
  static const int maxPaddingSize = blockSize;
}
