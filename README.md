
# react-native-secp256k1

## Getting started

`$ npm install react-native-secp256k1 --save`

### Mostly automatic installation

`$ react-native link react-native-secp256k1`

### Manual installation


#### iOS

1. In XCode, in the project navigator, right click `Libraries` ➜ `Add Files to [your project's name]`
2. Go to `node_modules` ➜ `react-native-secp256k1` and add `RNSecp256k1.xcodeproj`
3. In XCode, in the project navigator, select your project. Add `libRNSecp256k1.a` to your project's `Build Phases` ➜ `Link Binary With Libraries`
4. Run your project (`Cmd+R`)<

#### Android

1. Open up `android/app/src/main/java/[...]/MainActivity.java`
  - Add `import com.reactlibrary.RNSecp256k1Package;` to the imports at the top of the file
  - Add `new RNSecp256k1Package()` to the list returned by the `getPackages()` method
2. Append the following lines to `android/settings.gradle`:
  	```
  	include ':react-native-secp256k1'
  	project(':react-native-secp256k1').projectDir = new File(rootProject.projectDir, 	'../node_modules/react-native-secp256k1/android')
  	```
3. Insert the following lines inside the dependencies block in `android/app/build.gradle`:
  	```
      compile project(':react-native-secp256k1')
  	```


## Usage
```javascript
import RNSecp256k1 from 'react-native-secp256k1';

// TODO: What to do with the module?
RNSecp256k1;
```
  