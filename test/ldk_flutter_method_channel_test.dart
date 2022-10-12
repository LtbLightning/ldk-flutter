import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ldk_flutter/ldk_flutter_method_channel.dart';

void main() {
  MethodChannelLdkFlutter platform = MethodChannelLdkFlutter();
  const MethodChannel channel = MethodChannel('ldk_flutter');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await platform.getPlatformVersion(), '42');
  });
}
