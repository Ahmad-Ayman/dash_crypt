import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dash_crypt/dash_crypt.dart';

class SecureRandomUtils {
  /// Generates cryptographically secure random bytes of the specified length.
  ///
  /// [length]: The number of bytes to generate. Must be a non-negative value.
  /// Returns a `Uint8List` containing secure random bytes.
  static Uint8List generateSecureBytes(int length) {
    if (length < 0) {
      throw ArgumentError('Length must be a non-negative integer.');
    }

    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(length, (_) => random.nextInt(256)),
    );
  }

  /// Generates a secure random key for the specified AES key size.
  ///
  /// [keySize]: The AES key size in bits (128, 192, 256).
  /// Returns a `Uint8List` containing the key.
  static Uint8List generateSecureKey(int keySize) {
    if (![128, 192, 256].contains(keySize)) {
      throw ArgumentError(
          'Invalid AES key size. Must be 128, 192, or 256 bits.');
    }
    return generateSecureBytes(keySize ~/ 8);
  }

  /// Generates a secure random IV for the specified AES mode.
  ///
  /// [ivSize]: The required IV size in bytes (e.g., 12 for GCM, 16 for CBC).
  /// Returns a `Uint8List` containing the IV.
  static Uint8List generateSecureIV(int ivSize) {
    if (ivSize <= 0) {
      throw ArgumentError('IV size must be a positive integer.');
    }
    return generateSecureBytes(ivSize);
  }

  /// Helper to convert bytes to a hex string.
  static String bytesToHex(Uint8List bytes) {
    return hex.encode(bytes);
  }





  /// Helper to generate random bytes.
  static Uint8List generateSecureBytesForKey(KeySize size) {

    final random = Random.secure();
    int length=0;
    switch(size){
      case KeySize.aes128:
        length = 16;
        break;
      case KeySize.aes192:
        length = 24;
        break;
      case KeySize.aes256:
        length = 32;
        break;
    }
    return Uint8List.fromList(
      List<int>.generate(length, (_) => random.nextInt(256)),
    );
  }


}
