LOCAL_PATH := $(call my-dir)



include $(CLEAR_VARS)
LOCAL_MODULE:= FridaDummy
LOCAL_SRC_FILES := fridaDummy.c
include $(BUILD_SHARED_LIBRARY)



include $(CLEAR_VARS)
LOCAL_MODULE:=cocos2dExtractAssets
LOCAL_SRC_FILES := cocos2dExtractAssets.c
LOCAL_C_INCLUDES := include
LOCAL_LDLIBS := 
LOCAL_ARM_MODE := arm
#LOCAL_ALLOW_UNDEFINED_SYMBOLS := true
LOCAL_CFLAGS= -fno-exceptions -fno-stack-protector -z execstack
LOCAL_SHARED_LIBRARIES = FridaDummy
include $(BUILD_SHARED_LIBRARY)


