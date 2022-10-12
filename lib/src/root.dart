

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'package:path_provider/path_provider.dart';
import 'package:flutter/material.dart';
import 'package:isolate/ports.dart';
import 'package:ldk_flutter/ldk_flutter.dart';
import 'package:ldk_flutter/src/enums/network.dart';

class LdkFlutter {
  _startIsolate() async{

  }
  Future<bool> checkIfInitialized() async {
    var res = await loaderApi.checkRpcInit();
    return res;
  }
  Future<String> getNodeId() async {
    var res = await loaderApi.getNodeId();
    return res;
  }
  Future<String> ldkInit(
      {required String host,
      required int port,
      required String username,
      required String password,
      required Network network,
      required String storagePath}) async {
    final completer = Completer<String>();
    final sendPort = singleCompletePort(completer);
    final isolatePort = sendPort.nativePort;
    var res =  await  loaderApi.loadClient(
    host: host,
    port: port,
    username: username,
    password: password,
    isolatePort: isolatePort,
    network:network.name.toString(),
    path:storagePath,
    );
    if (res != 1) {
      completer.complete("Ldk init failed");
    }
    return completer.future;
  }

  getPlatformVersion() async{
    final path =await  getAppDocDirPath();
    final res = await ldkInit(
        host: "127.0.0.1",
        port: 18443,
        username: "polaruser",
        password: "polarpass",
        network:Network.REGTEST,
        storagePath: path).
    then((value) => debugPrint(value));
    return res;
  }
  /// Get app doc directory path for app.
  Future<String> getAppDocDirPath() async {
    final Directory _appDocDir = await getApplicationDocumentsDirectory();
    return _appDocDir.path;
  }
}
