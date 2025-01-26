import 'dart:convert';
import 'dart:typed_data';

class ConversionUtils {
  /// Converts a hex string to a `Uint8List`.
  static Uint8List hexToBytes(String hex) {
    final bytes = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      final byte = int.parse(hex.substring(i, i + 2), radix: 16);
      bytes.add(byte);
    }
    return Uint8List.fromList(bytes);
  }

  /// Converts a `Uint8List` to a hex string.
  static String bytesToHex(Uint8List bytes) {
    final buffer = StringBuffer();
    for (final byte in bytes) {
      buffer.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  /// Converts a base64 string to a `Uint8List`.
  static Uint8List base64ToBytes(String base64Str) {
    return base64.decode(base64Str);
  }

  /// Converts a `Uint8List` to a base64 string.
  static String bytesToBase64(Uint8List bytes) {
    return base64.encode(bytes);
  }

  /// Converts a plain string to a `Uint8List`.
  static Uint8List stringToBytes(String input) {
    return Uint8List.fromList(utf8.encode(input));
  }

  /// Converts a `Uint8List` back to a plain string.
  static String bytesToString(Uint8List bytes) {
    return utf8.decode(bytes);
  }
}
