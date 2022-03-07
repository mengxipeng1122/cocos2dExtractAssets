
# Test APK

I am using a popular game using Cocos2d-X for testing.    
[Download link](https://m.ie925.com/game/kpcl/10194.html)   
Game name: 放开那三国    
Package name : com.sincetimes.fknsg  

# How to use
## a. Install downloaded apk file to your Android device, and start frida server on your Android device.[How to setup your Android device with frida server](https://frida.re/docs/android/)  
## b. Compile Android JNI code   
```bash
    cd jni
    make
```
  NOTE: you need to modify the `NDKPATH` variable in file `jni/Makefile` to the actual path of your NDK. I am using NDK r15c.   
## c. Install required node modules
```bash
    cd .
    npm i
```
## d. Star game on your Android device and check game process
```bash
    frida-ps -Ua
```  
My game process is the following:
```
2234  放开那三国（送貂蝉）    com.sincetimes.fknsg
```
2234 -- PID   
放开那三国（送貂蝉） -- Process name   
com.sincetimes.fknsg -- Package name  
## e.Load typescript script to game process  
```bash
    cd . 
    frida -U -l _agent.js -n  "放开那三国（送貂蝉）" --no-pause 
```  
This script will list all encypted assets files in the package, and try to decrypt the first one, (You can mod the code do dump all files)


