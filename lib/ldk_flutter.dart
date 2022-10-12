
import 'ldk_flutter_platform_interface.dart';

class LdkFlutter {
  Future<String?> getPlatformVersion() {
    return LdkFlutterPlatform.instance.getPlatformVersion();
  }
}
