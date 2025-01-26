import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import '../../exceptions/encryption_exceptions.dart';
import '../../utils/enums.dart';

class AesEcb {
  final KeySize _keySize;

  AesEcb({
    required KeySize keySize,
  }) : _keySize = keySize;

  String encrypt({
    required String text,
    required String key,
  }) {
    final (textBytes, keyBytes) = _convertAndValidateInputs(text, key, encrypting: true);

    // Use PaddedBlockCipher for encryption
    final cipher = _createPaddedCipher(true, keyBytes);
    final encryptedBytes = cipher.process(textBytes);

    return base64.encode(encryptedBytes);
  }

  String decrypt({
    required String text,
    required String key,
  }) {
    final cipherBytes = base64.decode(text);
    final (_, keyBytes) = _convertAndValidateInputs(text, key, encrypting: false);

    // Use PaddedBlockCipher for decryption
    final cipher = _createPaddedCipher(false, keyBytes);
    final decryptedBytes = cipher.process(cipherBytes);

    return utf8.decode(decryptedBytes);
  }

  (Uint8List, Uint8List) _convertAndValidateInputs(String text, String key, {required bool encrypting}) {
    final keyBytes = Uint8List.fromList(utf8.encode(key));
    final textBytes = encrypting ? Uint8List.fromList(utf8.encode(text)) : base64.decode(text);

    _validateKeySize(keyBytes);

    return (textBytes, keyBytes);
  }

  void _validateKeySize(Uint8List keyBytes) {
    final expectedKeySize = _getKeySizeInBytes();
    if (keyBytes.length != expectedKeySize) {
      throw InvalidKeySizeException(
        'Invalid key length: ${keyBytes.length} bytes. Expected: $expectedKeySize bytes.',
      );
    }
  }

  pc.PaddedBlockCipher _createPaddedCipher(bool encrypt, Uint8List key) {
    final aes = pc.AESEngine();
    final ecb = pc.ECBBlockCipher(aes);
    final params = pc.KeyParameter(key);

    final paddedCipher = pc.PaddedBlockCipherImpl(pc.PKCS7Padding(), ecb);
    paddedCipher.init(encrypt, pc.PaddedBlockCipherParameters(params, null));
    return paddedCipher;
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