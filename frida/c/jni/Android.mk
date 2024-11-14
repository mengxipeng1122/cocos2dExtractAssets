LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE:=cocos2dExtractAssets
LOCAL_SRC_FILES := ../cocos2dExtractAssets.cpp
LOCAL_C_INCLUDES := include
LOCAL_LDLIBS := 
LOCAL_ARM_MODE := thumb
LOCAL_ALLOW_UNDEFINED_SYMBOLS := true
LOCAL_CFLAGS= -fno-exceptions -fno-stack-protector -z execstack
include $(BUILD_SHARED_LIBRARY)


