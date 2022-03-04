

NDKPATH=/mnt/axly/hackings/android-utils/android-ndk-r15c/

all:
	${NDKPATH}/ndk-build V=1

clean:
	${NDKPATH}/ndk-build clean

install: all
	adb push ../libs/armeabi-v7a/*.so /data/local/tmp

