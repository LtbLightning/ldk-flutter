import 'dart:ffi';
import 'dart:io';
import 'package:ldk_flutter/ldk_flutter.dart';
final DynamicLibrary dylib = Platform.isIOS
    ? DynamicLibrary.process()
    : Platform.isMacOS
    ? DynamicLibrary.executable()
    : DynamicLibrary.open('liblightning.so');

NativeLibrary  loaderApi = NativeLibrary(dylib);