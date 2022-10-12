import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'ldk_flutter_method_channel.dart';

abstract class LdkFlutterPlatform extends PlatformInterface {
  /// Constructs a LdkFlutterPlatform.
  LdkFlutterPlatform() : super(token: _token);

  static final Object _token = Object();

  static LdkFlutterPlatform _instance = MethodChannelLdkFlutter();

  /// The default instance of [LdkFlutterPlatform] to use.
  ///
  /// Defaults to [MethodChannelLdkFlutter].
  static LdkFlutterPlatform get instance => _instance;
  
  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [LdkFlutterPlatform] when
  /// they register themselves.
  static set instance(LdkFlutterPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
