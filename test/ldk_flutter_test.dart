import 'package:flutter_test/flutter_test.dart';
import 'package:ldk_flutter/ldk_flutter.dart';
import 'package:ldk_flutter/ldk_flutter_platform_interface.dart';
import 'package:ldk_flutter/ldk_flutter_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockLdkFlutterPlatform 
    with MockPlatformInterfaceMixin
    implements LdkFlutterPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final LdkFlutterPlatform initialPlatform = LdkFlutterPlatform.instance;

  test('$MethodChannelLdkFlutter is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelLdkFlutter>());
  });

  test('getPlatformVersion', () async {
    LdkFlutter ldkFlutterPlugin = LdkFlutter();
    MockLdkFlutterPlatform fakePlatform = MockLdkFlutterPlatform();
    LdkFlutterPlatform.instance = fakePlatform;
  
    expect(await ldkFlutterPlugin.getPlatformVersion(), '42');
  });
}
