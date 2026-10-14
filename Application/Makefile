.PHONY: all clean build_clean diagnostic

all: Dopamine.ipa

# Dedicated install/open diagnostic. This is NOT a RootHide jailbreak.
# It is compiled as a separate app with a distinct bundle ID, no privileged
# entitlements and a read-only UI; it never replaces stock Dopamine.
diagnostic: build-diagnostic/Build/Products/Debug-iphoneos/Dopamine.app
	@echo Packaging RootHide 3 install/open diagnostic (no jailbreak)
	xattr -rc build-diagnostic/Build/Products/Debug-iphoneos/Dopamine.app
	@# Do not ship the jailbreak bootstrap, package installers or binary payloads
	@# in a GUI-only installation test. Required linked frameworks stay intact.
	rm -f build-diagnostic/Build/Products/Debug-iphoneos/Dopamine.app/basebin.tar build-diagnostic/Build/Products/Debug-iphoneos/Dopamine.app/*.deb build-diagnostic/Build/Products/Debug-iphoneos/Dopamine.app/*.tar.zst
	@plutil -extract CFBundleIdentifier raw build-diagnostic/Build/Products/Debug-iphoneos/Dopamine.app/Info.plist | grep -qx 'com.gokuencinar.roothide3.diagnostic'
	ldid -SDopamine/Diagnostic.entitlements build-diagnostic/Build/Products/Debug-iphoneos/Dopamine.app/Dopamine
	ldid -s build-diagnostic/Build/Products/Debug-iphoneos/Dopamine.app
	rm -rf Payload RootHide3-Device-Test.ipa
	mkdir Payload
	cp -r build-diagnostic/Build/Products/Debug-iphoneos/Dopamine.app Payload/Dopamine.app
	zip -Ar RootHide3-Device-Test.ipa Payload
	rm -rf Payload

build-diagnostic/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild -scheme Dopamine -derivedDataPath build-diagnostic -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO PRODUCT_BUNDLE_IDENTIFIER=com.gokuencinar.roothide3.diagnostic INFOPLIST_KEY_CFBundleDisplayName='RootHide 3 Test' GCC_PREPROCESSOR_DEFINITIONS='RH3_INSTALLABLE_DIAGNOSTIC=1 ROOTHIDE3_BOOTSTRAP_READY=0'

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
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO GCC_PREPROCESSOR_DEFINITIONS='NIGHTLY=1 COMMIT_HASH=\"$(COMMIT_HASH)\"'
else
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO
endif

clean:
	rm -rf build build-diagnostic Payload Dopamine.ipa Dopamine.tipa RootHide3-Device-Test.ipa

build_clean:
	rm -rf Payload build

FORCE: ;
