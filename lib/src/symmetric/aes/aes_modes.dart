import 'dart:typed_data';

/// Abstract base class for AES encryption and decryption modes.
///
/// This class defines the structure that all AES mode implementations
/// must follow. Each mode is responsible for implementing the encryption
/// and decryption logic specific to its mode of operation (e.g., CBC, GCM).
abstract class AESModeStrategy {
  /// Encrypts the given plaintext using the provided key and initialization vector (IV).
  ///
  /// [plaintext]: The plaintext data to encrypt, as a UTF-8 string.
  /// [key]: The encryption key, as a `Uint8List`.
  /// [iv]: The initialization vector, as a `Uint8List`.
  ///
  /// Returns the encrypted data as a Base64-encoded string.
  String encrypt(String plaintext, Uint8List key, Uint8List iv);

  /// Decrypts the given ciphertext using the provided key and initialization vector (IV).
  ///
  /// [ciphertext]: The ciphertext data to decrypt, as a Base64-encoded string.
  /// [key]: The decryption key, as a `Uint8List`.
  /// [iv]: The initialization vector, as a `Uint8List`.
  ///
  /// Returns the decrypted data as a UTF-8 string.
  String decrypt(String ciphertext, Uint8List key, Uint8List iv);
}
