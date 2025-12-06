import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:uuid/uuid.dart';

class SignParams {
  String timestamp;
  String nonce;
  String operationId;
  String signature;

  SignParams({
    required this.timestamp,
    required this.nonce,
    required this.operationId,
    required this.signature,
  });
}

class SignUtil {
  /// Generate a random string with specified length
  static String randomString(int length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    final random = Random.secure();
    return List.generate(length, (index) => chars[random.nextInt(chars.length)]).join();
  }

  /// Generate UUID v4
  static String generateUuidV4() {
    const uuid = Uuid();
    return uuid.v4();
  }

  /// Generate HMAC-SHA256 signature for API requests
  static SignParams generateSign({
    required String method,
    required String path,
    required String body,
    required String secret,
    required int platform,
    required String deviceId,
    required String channel,
    required String packageName,
    required String version,
    required String brand,
    required String buildNumber,
    bool isGateway = false,
    String token = '',
  }) {
    // Generate nonce (16 random characters)
    final nonce = randomString(16);

    // Generate operationId (UUID v4)
    final operationId = generateUuidV4();

    // Generate timestamp (ISO 8601 format, UTC)
    final timestamp = DateTime.now().toUtc().toIso8601String();

    // Create payload by joining values with newline
    final payloadParts = [
      method,
      path,
      timestamp,
      nonce,
      body,
      platform.toString(),
      operationId,
      deviceId,
      channel,
      packageName,
      version,
      brand,
      buildNumber,
      if (!isGateway) token,
    ];

    final payload = payloadParts.join('\n');

    // Calculate HMAC-SHA256 signature
    final keyBytes = utf8.encode(secret);
    final messageBytes = utf8.encode(payload);
    final hmac = Hmac(sha256, keyBytes);
    final digest = hmac.convert(messageBytes);

    // Convert to hex string
    final signature = digest.toString();

    return SignParams(
      timestamp: timestamp,
      nonce: nonce,
      operationId: operationId,
      signature: signature,
    );
  }
}
