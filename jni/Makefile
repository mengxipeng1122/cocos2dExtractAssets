

NDKPATH=/mnt/axly/hackings/android-utils/android-ndk-r15c/

all:
	${NDKPATH}/ndk-build V=1

clean:
	${NDKPATH}/ndk-build clean

install: all
	if `adb shell getprop ro.product.cpu.abilist | grep arm64-v8a >/dev/null`;  then   \
        adb push ../libs/arm64-v8a//*.so /data/local/tmp;                   \
    else  \
        if `adb shell getprop ro.product.cpu.abilist | grep armeabi-v7a >/dev/null`;  then \
            adb push ../libs/armeabi-v7a/*.so /data/local/tmp;  \
        else \
            echo 'unsupported cpu'; exit -1; \
        fi \
    fi

