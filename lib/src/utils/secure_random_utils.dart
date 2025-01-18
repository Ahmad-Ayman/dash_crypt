import 'dart:math';
import 'dart:typed_data';

class SecureRandomUtils {
  /// Generates a secure random byte array of the specified length.
  static Uint8List generateSecureBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(length, (_) => random.nextInt(256)),
    );
  }
}
