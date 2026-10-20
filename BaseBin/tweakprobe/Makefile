CC = clang
TARGET = rh3tweakprobe
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)

all: $(TARGET)

$(TARGET): main.c
	$(CC) -arch arm64 -arch arm64e -isysroot $(SDK) -miphoneos-version-min=15.0 -O2 -o $@ $<
	ldid -Cadhoc -S $@

clean:
	rm -f $(TARGET)

.PHONY: all clean
