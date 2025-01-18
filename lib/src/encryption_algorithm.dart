/// Interface for generic encryption algorithms.
abstract class EncryptionAlgorithm {
  /// Encrypts the given plaintext using the provided key.
  String encrypt(String plaintext, String key, {String? iv});

  /// Decrypts the given ciphertext using the provided key.
  String decrypt(String ciphertext, String key, {String? iv});

  /// Generates a secure random key.
  String generateKey();
}
