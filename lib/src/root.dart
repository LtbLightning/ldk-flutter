

import 'package:ldk_flutter/ldk_flutter.dart';

class LdkFlutter {
  Future<String> getPlatformVersion() async {
    await  loaderApi.ldkIni(
      host: "127.0.0.1",
      port: 18443,
      username: "polaruser",
      password: "polarpass",
      network:"regtest",
      storagePath: "/data/user/0/com.example.ldk_rust_bridge_example/app_flutter/io.ldk.f",
    ).then((value) => value);
    return "";
  }

}
