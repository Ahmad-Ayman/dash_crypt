/// Exception thrown when an invalid key size is provided.
class InvalidKeySizeException implements Exception {
  final String message;

  InvalidKeySizeException([this.message = 'Invalid key size provided.']);

  @override
  String toString() => 'InvalidKeySizeException: $message';
}

/// Exception thrown when an invalid IV (Initialization Vector) size is provided.
class InvalidIVSizeException implements Exception {
  final String message;

  InvalidIVSizeException([this.message = 'Invalid IV size provided.']);

  @override
  String toString() => 'InvalidIVSizeException: $message';
}

/// Exception thrown when the input data is not properly aligned (e.g., for block modes without padding).
class InvalidInputSizeException implements Exception {
  final String message;

  InvalidInputSizeException([this.message = 'Input size is not valid for the chosen mode.']);

  @override
  String toString() => 'InvalidInputSizeException: $message';
}

/// Exception thrown for unsupported padding schemes.
class UnsupportedPaddingException implements Exception {
  final String message;

  UnsupportedPaddingException([this.message = 'Unsupported padding scheme.']);

  @override
  String toString() => 'UnsupportedPaddingException: $message';
}
/// Exception thrown for unsupported padding schemes.
class InvalidHexEncodingException implements Exception {
  final String message;

  InvalidHexEncodingException([this.message = 'Unsupported padding scheme.']);

  @override
  String toString() => 'UnsupportedPaddingException: $message';
}

/// Exception thrown when encryption or decryption fails unexpectedly.
class EncryptionException implements Exception {
  final String message;

  EncryptionException([this.message = 'An error occurred during encryption or decryption.']);

  @override
  String toString() => 'EncryptionException: $message';
}

class InvalidPaddingException implements Exception {
  final String message;

  InvalidPaddingException([this.message = 'An error occurred during Padding.']);

  @override
  String toString() => 'InvalidPaddingException: $message';
}
