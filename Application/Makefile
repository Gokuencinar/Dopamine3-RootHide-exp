.PHONY: all clean build_clean diagnostic

all: Dopamine.ipa

# Minimal UIKit-only install/open app. Do not link Dopamine, kernel exploits,
# BaseBin, jailbreak hooks, or any other privileged RootHide components.
diagnostic: FORCE
	@echo "Building isolated RootHide 3 install/open diagnostic (no jailbreak)"
	mkdir -p build-diagnostic/Payload/Dopamine.app
	cp Diagnostic/Info.plist build-diagnostic/Payload/Dopamine.app/Info.plist
	xcrun --sdk iphoneos clang -arch arm64 -miphoneos-version-min=15.0 -fobjc-arc -fmodules -isysroot "$$(xcrun --sdk iphoneos --show-sdk-path)" -framework UIKit -framework Foundation Diagnostic/main.m -o build-diagnostic/Payload/Dopamine.app/Dopamine
	ldid -SDopamine/Diagnostic.entitlements build-diagnostic/Payload/Dopamine.app/Dopamine
	@plutil -extract CFBundleIdentifier raw build-diagnostic/Payload/Dopamine.app/Info.plist | grep -qx 'com.gokuencinar.roothide3.diagnostic'
	rm -f RootHide3-Device-Test.ipa
	cd build-diagnostic && zip -qry ../RootHide3-Device-Test.ipa Payload

Dopamine.ipa: build/Build/Products/Debug-iphoneos/Dopamine.app
	@echo Ad-Hoc signing Dopamine
	xattr -rc build/Build/Products/Debug-iphoneos/Dopamine.app
	ldid -SDopamine/Dopamine.entitlements build/Build/Products/Debug-iphoneos/Dopamine.app/Dopamine
	ldid -s build/Build/Products/Debug-iphoneos/Dopamine.app
	rm -rf Payload Dopamine.ipa
	mkdir Payload
	cp -r build/Build/Products/Debug-iphoneos/Dopamine.app Payload/Dopamine.app
	zip -Ar Dopamine.ipa Payload
	rm -rf Payload
	rm -rf Dopamine.tipa
	cp Dopamine.ipa Dopamine.tipa

# The explicit RootHide build selector takes priority over NIGHTLY. The
# latter only adds metadata; disabling nightly must never select stock
# Dopamine's bundle ID or re-enable its bootstrap on a RootHide build.
ROOTHIDE_BOOTSTRAP_GATE := 0
ROOTHIDE_EXPERIMENT_ID := com.gokuencinar.roothide3.fulltest
ROOTHIDE_EXPERIMENT_NAME := RootHide 3 Experimental
ifeq ($(ROOTHIDE_HARDWARE_TEST),YES)
ifneq ($(ROOTHIDE_EXPERIMENTAL_BUILD),1)
$(error ROOTHIDE_HARDWARE_TEST=YES requires ROOTHIDE_EXPERIMENTAL_BUILD=1)
endif

# ccache only accelerates individual compile operations. Never cache Xcode's
# DerivedData, ldid output, IPA or BaseBin trustcache between Actions runs.
# This must be explicitly enabled by CI after installing ccache.
ifeq ($(RH3_CCACHE),1)
RH3_XCODE_CCACHE_ARGS := C_COMPILER_LAUNCHER=$(shell command -v ccache) CXX_COMPILER_LAUNCHER=$(shell command -v ccache)
endif
# Dangerous manual-only build. Never set in the scheduled/push CI.
ROOTHIDE_BOOTSTRAP_GATE := 1
ROOTHIDE_EXPERIMENT_ID := com.gokuencinar.roothide3.hardwarebeta
ROOTHIDE_EXPERIMENT_NAME := RootHide 3 Hardware Beta
endif

ifeq ($(NIGHTLY), 1)
DOPAMINE_NIGHTLY_DEFINITIONS := NIGHTLY=1 COMMIT_HASH=\"$(COMMIT_HASH)\"
endif

ifeq ($(ROOTHIDE_EXPERIMENTAL_BUILD), 1)
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	@echo "Building full RootHide 3 experimental app with protected jailbreak entrypoint"
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO RH3_APP_BUNDLE_IDENTIFIER=$(ROOTHIDE_EXPERIMENT_ID) RH3_APP_DISPLAY_NAME='$(ROOTHIDE_EXPERIMENT_NAME)' GCC_PREPROCESSOR_DEFINITIONS='RH3_FULL_APP_EXPERIMENTAL=1 ROOTHIDE3_BOOTSTRAP_READY=$(ROOTHIDE_BOOTSTRAP_GATE) $(DOPAMINE_NIGHTLY_DEFINITIONS)' $(RH3_XCODE_CCACHE_ARGS)
else ifeq ($(NIGHTLY), 1)
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO GCC_PREPROCESSOR_DEFINITIONS='$(DOPAMINE_NIGHTLY_DEFINITIONS)' $(RH3_XCODE_CCACHE_ARGS)
else
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO $(RH3_XCODE_CCACHE_ARGS)
endif

clean:
	rm -rf build build-diagnostic Payload Dopamine.ipa Dopamine.tipa RootHide3-Device-Test.ipa

build_clean:
	rm -rf Payload build

FORCE: ;
