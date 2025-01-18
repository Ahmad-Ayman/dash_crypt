/// Interface for generic encryption algorithms.
///
/// Provides a consistent contract for encryption algorithms, ensuring that all
/// implementing classes provide methods for encryption, decryption, and key generation.
abstract class EncryptionAlgorithm {
  /// Encrypts the given plaintext using the provided key.
  ///
  /// [plaintext]: The plaintext to encrypt.
  /// [key]: The Base64-encoded encryption key.
  /// [iv]: (Optional) The Base64-encoded initialization vector (IV), if required by the algorithm.
  ///
  /// Returns a Base64-encoded ciphertext.
  String encrypt(String plaintext, String key, {String? iv});

  /// Decrypts the given ciphertext using the provided key.
  ///
  /// [ciphertext]: The Base64-encoded ciphertext to decrypt.
  /// [key]: The Base64-encoded decryption key.
  /// [iv]: (Optional) The Base64-encoded initialization vector (IV), if required by the algorithm.
  ///
  /// Returns the decrypted plaintext.
  String decrypt(String ciphertext, String key, {String? iv});

  /// Generates a secure random encryption key.
  ///
  /// Returns a Base64-encoded key suitable for the algorithm.
  String generateKey();
}
