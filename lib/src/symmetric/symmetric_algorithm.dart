import '../encryption_algorithm.dart';

/// Interface for symmetric encryption algorithms.
abstract class SymmetricAlgorithm extends EncryptionAlgorithm {
  /// Generates a secure random initialization vector (IV).
  String generateIV();
}
