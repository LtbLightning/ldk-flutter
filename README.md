## Ldk-Flutter
A Flutter version of the Lightning Development Kit (https://lightningdevkit.org/)


## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Building Binary Files](#building-binary-files)
- [Usage](#usage)

## Requirements

### Flutter

* Flutter version :  3.0 or higher
* Dart version    :  2.17.1 or higher

### Android

* Android minSdkVersion.     : API 23 or higher.
* Android Target SDK version : API 29.
* Android Gradle Plugin      : 3.0.0 or greater.


### iOS

* iOS Base SDK      : 12 or greater.
* Deployment target : iOS 12.0 or greater.
* Cocoapods         : 1.11.3 or greater


## Installation

From Github (copy and paste the following code to pubsepc.yaml):

```bash
ldk-flutter:
    git:
      url: https://github.com/LtbLightning/ldk-flutter.git
      ref: main
```

## Building Binary Files
```
Please re-built your app in an android device or an emulator, after including the dependency in your pubspec.yaml, to build the necessary files.
```

### Configuring iOS

Please navigate to the iOS folder in your project run the following command:
```
pod install
```

## Usage

```dart
import 'package:ldk_flutter/ldk_flutter.dart';
```
