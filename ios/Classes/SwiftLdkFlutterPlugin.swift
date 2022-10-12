import Flutter
import UIKit

public class SwiftLdkFlutterPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "ldk_flutter", binaryMessenger: registrar.messenger())
    let instance = SwiftLdkFlutterPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func dummyMethodToEnforceBundling() {
            dummy_method_to_enforce_bundling();
   }
  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {}
}
