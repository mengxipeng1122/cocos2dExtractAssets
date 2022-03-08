
# Test APK

I am using a popular game using Cocos2d-X for testing.    
[Download link](https://m.ie925.com/game/kpcl/10194.html)   
Game name: 放开那三国    
Package name : com.sincetimes.fknsg  

# How to use
## a. Install downloaded apk file to your Android device, and start frida server on your Android device.[How to setup your Android device with frida server](https://frida.re/docs/android/)  
## b. Connet your android device to you computer, and compile Android JNI code   
```bash
    cd jni
    make install # this command will push compiled .so to your android device
```
  NOTE: you need to modify the `NDKPATH` variable in file `jni/Makefile` to the actual path of your NDK. I am using NDK r15c.   
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


