import 'dart:isolate';

import 'package:ldk_flutter/ldk_flutter.dart';

class LdkNodeArgs {
  final String host;
  final int port;
  final String username;
  final String password;
  final Network  network;
  final String path;
  final  SendPort isolatePort;

  LdkNodeArgs(
      {
        required this.host,
        required this.port,
        required this.isolatePort,
        required this.username,
        required this.password,
        required this.network,
        required this.path});
}