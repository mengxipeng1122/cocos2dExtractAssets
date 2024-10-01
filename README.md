
# Test APK

I am using a popular game using Cocos2d-X for testing.    
[Download link](https://apkpure.com/fang-kai-na-san-guo-song-diao-chan/com.sincetimes.fknsg/downloading/7.0.0) 
Game name: 放开那三国    
Package name : com.sincetimes.fknsg  

# How to use
## a. Install downloaded apk file to your Android device, and start frida server on your Android device.[How to setup your Android device with frida server](https://frida.re/docs/android/) . And besure your android device have a good Intenet connection, or the app will not start.
## b. Connet your android device to you computer, and compile Android JNI code   
```bash
    export NDKPATH=<your ndk path for android-ndk-r15c>
    cd jni
    make install # this command will push compiled .so to your android device
```
## c. Install required node modules
```bash
    cd .
    npm i
```
## d.Execute typescript script 
```bash
    cd . 
    frida -U -f com.sincetimes.fknsg -l _agent.js --no-pause
```  
This script will list all encypted assets files in the package, and try to decrypt them, and dump decrypted files to your Android device.   


## trouble shooting
1. If you see error message like this:
```bash
    error while loading shared libraries: libncurses.so.5 : cannot open shared object file: No such file or directory 
```

This is because your machine has no `libncurses.so.5` file, you can install it by `apt install ncurses-dev` in termux, or `apt install libncurses5` in ubuntu.
Or just link `libncurses.so.5` to `libncurses.so`
 just link `libtinfo.so.5` to `libtinfo.so`
You can find these files in your linux system at `/usr/lib/x86_64-linux-gnu`




