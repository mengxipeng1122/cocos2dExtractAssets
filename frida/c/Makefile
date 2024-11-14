

ifndef NDK_PATH
    $(error NDK_PATH is not defined. Please set the NDK_PATH variable to the path of your Android NDK installation.)
endif

# check if NDK_PATH is valid
ifeq ($(shell test -d $(NDK_PATH) && echo "yes"),)
    $(error NDK_PATH is not a valid directory: $(NDK_PATH))
endif

install: build
	@if `adb shell getprop ro.product.cpu.abilist | grep arm64-v8a >/dev/null`;  then   \
        adb push ./libs/arm64-v8a//*.so /data/local/tmp;                   \
    else  \
        if `adb shell getprop ro.product.cpu.abilist | grep armeabi-v7a >/dev/null`;  then \
            adb push ./libs/armeabi-v7a/*.so /data/local/tmp;  \
        else \
            echo 'unsupported cpu'; exit -1; \
        fi \
    fi


build:
	${NDK_PATH}/ndk-build V=1

clean:
	${NDK_PATH}/ndk-build clean
