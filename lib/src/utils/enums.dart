/// Enumeration for AES padding schemes.
enum AesPadding {
  pkcs7,    // PKCS7 padding
  noPadding // No padding
}

/// Enumeration for AES encryption modes.
enum AesMode {
  cbc,  // Cipher Block Chaining
  ecb,  // Electronic Codebook
  cfb,  // Cipher Feedback
  gcm,  // Galois/Counter Mode
}

/// Enumeration for supported key sizes in AES.
enum KeySize {
  aes128, // 128-bit key
  aes192, // 192-bit key
  aes256, // 256-bit key
}

enum Classical{
  affine,
  caesar,
  columnarTransposition,
  monoalphabetic,
  playfair,
  railFence,
  vigenere
}
/// Example usage of these enums in your DashCrypt API:
/// DashCrypt.AES128CBC(padding: AesPadding.pkcs7).encrypt(...);
