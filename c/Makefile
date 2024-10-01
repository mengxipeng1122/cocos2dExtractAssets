

ifndef NDKPATH
    $(error NDKPATH is not defined. Please set the NDKPATH variable to the path of your Android NDK installation.)
endif

install: build
	if `adb shell getprop ro.product.cpu.abilist | grep arm64-v8a >/dev/null`;  then   \
        adb push ./libs/arm64-v8a//*.so /data/local/tmp;                   \
    else  \
        if `adb shell getprop ro.product.cpu.abilist | grep armeabi-v7a >/dev/null`;  then \
            adb push ./libs/armeabi-v7a/*.so /data/local/tmp;  \
        else \
            echo 'unsupported cpu'; exit -1; \
        fi \
    fi


build:
	${NDKPATH}/ndk-build V=1

clean:
	${NDKPATH}/ndk-build clean
