TARGET = libjailbreak.dylib

BUILD_STANDALONE ?= 0

CC = clang

CFLAGS = -framework Foundation -framework CoreServices -framework Security -framework IOKit -framework IOSurface -framework IOMobileFramebuffer -framework CoreGraphics -framework ImageIO -lMobileGestalt -I../.include -I../_external/modules/litehook/src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -dynamiclib -install_name @loader_path/$(TARGET) -I$(shell brew --prefix)/opt/libarchive/include -D BUILD_STANDALONE=$(BUILD_STANDALONE)
LDFLAGS = -larchive -lbsm -L../.build -F ../_external/frameworks -lchoma

# Clang handles both target architectures when linking the C++ source with
# the Objective-C and C sources; compiling one multi-arch .o would not work.
# Dopamine 3's launchdhook already owns the crash reporter. The RootHide 2
# copy exports the same function names with an incompatible pause/resume ABI;
# do not link a second crash reporter into libjailbreak.
ROOTHIDE_SOURCES = $(filter-out src/roothider/crashreporter.m,$(wildcard src/roothider/*.c src/roothider/*.m src/roothider/*.cpp))
# The active port uses Dopamine 3's sandbox/credential primitives. These
# unused donor implementations write namecache/vnode layouts from iOS 16;
# do not ship them as callable kernel-patching entrypoints on newer kernels.
ROOTHIDE_SOURCES := $(filter-out src/roothider/unsandbox.m src/roothider/unsandbox1.m src/roothider/unsandbox2.m,$(ROOTHIDE_SOURCES))
LDFLAGS += -lc++

sign: $(TARGET)
	@ldid -Cadhoc -S $<

$(TARGET): $(wildcard src/*.c src/*.m src/*.S ../_external/modules/litehook/src/*.c) $(ROOTHIDE_SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
