#import "LdkFlutterPlugin.h"
#import "bindings.h"
#if __has_include(<ldk_flutter/ldk_flutter-Swift.h>)
#import <ldk_flutter/ldk_flutter-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "ldk_flutter-Swift.h"
#endif

@implementation LdkFlutterPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftLdkFlutterPlugin registerWithRegistrar:registrar];
}
@end
