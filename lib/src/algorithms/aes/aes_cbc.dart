import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import '../../exceptions/encryption_exceptions.dart';
import '../../utils/conversion_utils.dart';
import '../../utils/enums.dart';

class AES_CBC {
  final KeySize _keySize;

  AES_CBC({
    required KeySize keySize,
  }) : _keySize = keySize {
    if (!KeySize.values.contains(keySize)) {
      throw ArgumentError('Invalid KeySize: $keySize');
    }
  }

  String encrypt({
    required String text,
    required String key,
    required String iv,
  }) {
    final (textBytes, keyBytes, ivBytes) = _convertAndValidateInputs(text, key, iv, encrypting: true);

    // Use PaddedBlockCipher for encryption
    final cipher = _createPaddedCipher(true, keyBytes, ivBytes);
    final encryptedBytes = cipher.process(textBytes);

    // print('Raw ciphertext bytes: $encryptedBytes');
    final encrypted = base64.encode(encryptedBytes);
    // print('Encrypted Base64 output: $encrypted');
    return encrypted;
  }

  String decrypt({
    required String text,
    required String key,
    required String iv,
  }) {
    final cipherBytes = base64.decode(text);
    // print('Decoded Base64 ciphertext bytes: $cipherBytes');

    final (_, keyBytes, ivBytes) = _convertAndValidateInputs(text, key, iv, encrypting: false);

    // Use PaddedBlockCipher for decryption
    final cipher = _createPaddedCipher(false, keyBytes, ivBytes);
    final decryptedBytes = cipher.process(cipherBytes);

    // print('Decrypted bytes (before removing padding): $decryptedBytes');
    return utf8.decode(decryptedBytes);
  }

  (Uint8List, Uint8List, Uint8List) _convertAndValidateInputs(
      String text,
      String key,
      String iv,
      {required bool encrypting}
      ) {
    final keyBytes = _convertToBytes(key);
    final ivBytes = _convertToBytes(iv);
    final textBytes = encrypting ? utf8.encode(text) : base64.decode(text);

    _validateKeySize(keyBytes);
    _validateIVSize(ivBytes);

    return (Uint8List.fromList(textBytes), keyBytes, ivBytes);
  }

  Uint8List _convertToBytes(String input) {
    return input.length % 2 == 0 && RegExp(r'^[0-9a-fA-F]+\$').hasMatch(input)
        ? ConversionUtils.hexToBytes(input)
        : Uint8List.fromList(utf8.encode(input));
  }

  void _validateKeySize(Uint8List keyBytes) {
    final expectedKeySize = _getKeySizeInBytes();
    if (keyBytes.length != expectedKeySize) {
      throw InvalidKeySizeException(
          'Invalid key length: ${keyBytes.length} bytes. Expected: $expectedKeySize bytes.');
    }
  }

  void _validateIVSize(Uint8List ivBytes) {
    if (ivBytes.length != 16) {
      throw InvalidIVSizeException('Invalid IV length: ${ivBytes.length} bytes (must be 16 bytes).');
    }
  }

  pc.PaddedBlockCipher _createPaddedCipher(bool encrypt, Uint8List key, Uint8List iv) {
    final aes = pc.AESEngine();
    final cbc = pc.CBCBlockCipher(aes);
    final params = pc.ParametersWithIV(pc.KeyParameter(key), iv);

    final paddedCipher = pc.PaddedBlockCipherImpl(pc.PKCS7Padding(), cbc);
    paddedCipher.init(encrypt, pc.PaddedBlockCipherParameters(params, null));
    return paddedCipher;
  }

  int _getKeySizeInBytes() {
    switch (_keySize) {
      case KeySize.aes128:
        return 16;
      case KeySize.aes192:
        return 24;
      case KeySize.aes256:
        return 32;
    }
  }
}
