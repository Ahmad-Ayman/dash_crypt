import 'package:dash_crypt/src/utils/secure_random_utils.dart';

import '../dash_crypt.dart';
import 'algorithms/aes/aes_index.dart';
import 'algorithms/classical/classical_index.dart';

class DashCrypt {
  // AES Algorithms
  static AesCbc AES__CBC({required KeySize keySize}) => AesCbc(keySize: keySize);


  static AesEcb AES__ECB({required KeySize keySize}) => AesEcb(keySize: keySize);

  static Aesgcm AES__GCM({required KeySize keySize}) => Aesgcm(keySize: keySize);

  static AesCfb AES__CFB({required KeySize keySize}) => AesCfb(keySize: keySize);

  // Classic Algorithms
  static final Caesar = CaesarCipher();
  static final Vigenere = VigenereCipher();
  static final Monoalphabetic = MonoalphabeticCipher();
  static final ColumnarTransposition = ColumnarTranspositionCipher();
  static final Playfair = PlayfairCipher();
  static final RailFence = RailFenceCipher();
  static final Affine = AffineCipher();

  /// Generates a secure random IV based on the AES algorithm name.
  /// [algorithmName] must be one of the AES algorithms: CBC, CFB, GCM, .
  static String generateIV(AesMode mode) {
    int ivSize;

    switch (mode) {
      case AesMode.cbc:
      case AesMode.cfb:
        ivSize = 16; // 16 bytes for these algorithms
        break;
      case AesMode.gcm:
        ivSize = 12; // 12 bytes for GCM
        break;
      default:
        throw ArgumentError('Unsupported algorithm: ${mode.name
        }. Supported: CBC, CFB, GCM.');
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
