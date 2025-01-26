import 'dart:convert';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart' as enc;
import '../../exceptions/encryption_exceptions.dart';
import '../../utils/enums.dart';

class AesCfb {
  final KeySize _keySize;

  AesCfb({
    required KeySize keySize,
  }) : _keySize = keySize;

  String encrypt({
    required String text,
    required String key,
    required String iv,
  }) {
    final keyBytes = _generateKey(key);
    final ivBytes = _generateIV(iv);

    try {
      final encrypter = enc.Encrypter(enc.AES(keyBytes, mode: enc.AESMode.cfb64));
      final ivObject = enc.IV(ivBytes.bytes);

      final encrypted = encrypter.encrypt(text, iv: ivObject);
      return encrypted.base64;
    } catch (e) {
      throw EncryptionException('Encryption failed: ${e.toString()}');
    }
  }

  String decrypt({
    required String text,
    required String key,
    required String iv,
  }) {
    final keyBytes = _generateKey(key);
    final ivBytes = _generateIV(iv);

    try {
      final encrypter = enc.Encrypter(enc.AES(keyBytes, mode: enc.AESMode.cfb64));
      final ivObject = enc.IV(ivBytes.bytes);

      final decrypted = encrypter.decrypt64(text, iv: ivObject);
      return decrypted;
    } catch (e) {
      throw EncryptionException('Decryption failed: ${e.toString()}');
    }
  }

  enc.Key _generateKey(String key) {
    final expectedKeySize = _getKeySizeInBytes();
    final keyBytes = Uint8List.fromList(utf8.encode(key));

    if (keyBytes.length != expectedKeySize) {
      throw InvalidKeySizeException(
        'Invalid key size: expected $expectedKeySize bytes, but got ${keyBytes.length} bytes.',
      );
    }

    return enc.Key(keyBytes);
  }

  enc.IV _generateIV(String iv) {
    final ivBytes = Uint8List.fromList(utf8.encode(iv));

    if (ivBytes.length != 16) {
      throw InvalidIVSizeException(
        'Invalid IV size: expected 16 bytes, but got ${ivBytes.length} bytes.',
      );
    }

    return enc.IV(ivBytes);
  }

  int _getKeySizeInBytes() {
    switch (_keySize) {
      case KeySize.aes128:
        return 16; // 128-bit
      case KeySize.aes192:
        return 24; // 192-bit
      case KeySize.aes256:
        return 32; // 256-bit
    }
  }
}
