import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'ldk_flutter_platform_interface.dart';

/// An implementation of [LdkFlutterPlatform] that uses method channels.
class MethodChannelLdkFlutter extends LdkFlutterPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('ldk_flutter');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
