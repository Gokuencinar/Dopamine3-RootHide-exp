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

ifeq ($(NIGHTLY), 1)
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
ifeq ($(ROOTHIDE_EXPERIMENTAL_BUILD), 1)
	@echo "Building full RootHide 3 experimental app with protected jailbreak entrypoint"
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO PRODUCT_BUNDLE_IDENTIFIER=com.gokuencinar.roothide3.fulltest INFOPLIST_KEY_CFBundleDisplayName='RootHide 3 Experimental' GCC_PREPROCESSOR_DEFINITIONS='NIGHTLY=1 RH3_FULL_APP_EXPERIMENTAL=1 ROOTHIDE3_BOOTSTRAP_READY=0 COMMIT_HASH=\"$(COMMIT_HASH)\"'
else
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO GCC_PREPROCESSOR_DEFINITIONS='NIGHTLY=1 COMMIT_HASH=\"$(COMMIT_HASH)\"'
endif
else
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO
endif

clean:
	rm -rf build build-diagnostic Payload Dopamine.ipa Dopamine.tipa RootHide3-Device-Test.ipa

build_clean:
	rm -rf Payload build

FORCE: ;
