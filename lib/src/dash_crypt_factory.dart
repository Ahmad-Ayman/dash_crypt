import 'package:dash_crypt/src/utils/secure_random_utils.dart';

import '../dash_crypt.dart';
import 'algorithms/aes/aes_index.dart';
import 'algorithms/classical/classical_index.dart';

class DashCrypt {
  // AES Algorithms
  static AES_CBC AES__CBC({required KeySize keySize}) => AES_CBC(keySize: keySize);


  static AES_ECB AES__ECB({required KeySize keySize}) => AES_ECB(keySize: keySize);

  static AES_GCM AES__GCM({required KeySize keySize}) => AES_GCM(keySize: keySize);

  static AES_CFB AES__CFB({required KeySize keySize}) => AES_CFB(keySize: keySize);

  // Classic Algorithms
  static final Caesar = CaesarCipher();
  static final Vigenere = VigenereCipher();
  static final Monoalphabetic = MonoalphabeticCipher();
  static final ColumnarTransposition = ColumnarTranspositionCipher();
  static final Playfair = PlayfairCipher();
  static final RailFence = RailFenceCipher();
  static final Affine = AffineCipher();

  /// Generates a secure random IV based on the AES algorithm name.
  /// [algorithmName] must be one of the AES algorithms: CBC, CFB, GCM, or OFB.
  static String generateIV(AesMode mode) {
    int ivSize;

    switch (mode) {
      case AesMode.cbc:
      case AesMode.cfb:
      case AesMode.ecb:
        ivSize = 16; // 16 bytes for these algorithms
        break;
      case AesMode.gcm:
        ivSize = 12; // 12 bytes for GCM
        break;
      default:
        throw ArgumentError('Unsupported algorithm: ${mode.name
        }. Supported: CBC, CFB, OFB, GCM.');
    }

    final randomBytes = SecureRandomUtils.generateSecureBytes(ivSize);
    return SecureRandomUtils.bytesToHex(randomBytes);
  }

  /// Generates a secure random key of the specified size.
  /// [size] must be 16, 24, or 32 bytes (128-bit, 192-bit, or 256-bit).
  static String generateKey(KeySize size) {
    if (size != KeySize.aes128 && size != KeySize.aes192 && size != KeySize.aes256) {
      throw ArgumentError('Key size must be (128-bit, 192-bit, 256-bit).');
    }
    final randomBytes = SecureRandomUtils.generateSecureBytesForKey(size);
    return SecureRandomUtils.bytesToHex(randomBytes);
  }
}
