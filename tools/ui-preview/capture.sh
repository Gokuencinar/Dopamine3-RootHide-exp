#!/bin/bash
set -euo pipefail
mkdir -p ui-preview/Payload/RootHidePreview.app ui-preview/captures
app="$PWD/ui-preview/Payload/RootHidePreview.app"
source_root="$PWD/Application/Dopamine"
sdk="$(xcrun --sdk iphonesimulator --show-sdk-path)"
arch="$(uname -m)"
python3 - "$app" <<'PY'
import plistlib,sys
from pathlib import Path
p=Path(sys.argv[1])/'Info.plist'
p.write_bytes(plistlib.dumps(dict(CFBundleExecutable='RootHidePreview',CFBundleIdentifier='com.gokuencinar.roothide3.uipreview',CFBundleName='UI Preview',CFBundleVersion='1',CFBundleShortVersionString='1.0',CFBundlePackageType='APPL',CFBundleDevelopmentRegion='es',MinimumOSVersion='18.0',UIDeviceFamily=[1],UILaunchScreen={},UIRequiresFullScreen=True,UISupportedInterfaceOrientations=['UIInterfaceOrientationPortrait'])))
PY
xcrun --sdk iphonesimulator clang -target "$arch-apple-ios18.0-simulator" -isysroot "$sdk" \
  -fobjc-arc -fmodules -Wno-deprecated-declarations \
  -Itools/ui-preview -Itools/ui-preview/Preferences -I"$source_root/UI" -I"$source_root/UI/ActionMenu" \
  -I"$source_root/UI/Settings/Specifiers" -I"$source_root/UI/Themes" -I"$source_root/Jailbreak" -I"$source_root/Extensions" \
  -framework UIKit -framework Foundation -framework CoreImage -framework QuartzCore \
  tools/ui-preview/main.m "$source_root/UI/DOGlobalAppearance.m" "$source_root/UI/DOHeaderView.m" \
  "$source_root/UI/ActionMenu/DOActionMenuButton.m" "$source_root/UI/ActionMenu/DOActionMenuView.m" \
  "$source_root/UI/Settings/Specifiers/DOCreditsCell.m" "$source_root/UI/Settings/Specifiers/DOHeaderCell.m" \
  "$source_root/UI/Themes/DOTheme.m" "$source_root/UI/Themes/DOThemeManager.m" "$source_root/Extensions/UIImage+Blur.m" \
  -o "$app/RootHidePreview"
cp "$source_root/UI/Settings/Credits.plist" "$source_root/UI/Themes/Themes.plist" "$app/"
cp "$source_root/Assets.xcassets/Dopamine.imageset/"*.png "$app/"
cp "$source_root/Assets.xcassets/Background/Background_Green.imageset/green.jpg" "$app/Background_Green.jpg"
mkdir -p "$app/es.lproj"
cp "$source_root/es.lproj/Localizable.strings" "$app/es.lproj/"
codesign --force --sign - "$app"
xcrun simctl list -j > ui-preview/simulator-inventory.json
runtime="$(python3 - <<'PY'
import json
d=json.load(open('ui-preview/simulator-inventory.json'))
choices=[r for r in d['runtimes'] if r.get('isAvailable') and 'iOS' in r['name']]
if not choices: raise SystemExit('No installed iOS simulator runtime; screenshots unavailable')
print(sorted(choices,key=lambda r:tuple(map(int,r['version'].split('.'))))[-1]['identifier'])
PY
)"
device="$(xcrun simctl create RootHide-UI-Preview com.apple.CoreSimulator.SimDeviceType.iPhone-16 "$runtime")"
trap 'xcrun simctl shutdown "$device" || true; xcrun simctl delete "$device" || true' EXIT
xcrun simctl boot "$device"
xcrun simctl bootstatus "$device" -b
xcrun simctl status_bar "$device" override --time 9:41 --dataNetwork wifi --wifiMode active --wifiBars 3 --batteryState charged --batteryLevel 100
xcrun simctl install "$device" "$app"
xcrun simctl launch "$device" com.gokuencinar.roothide3.uipreview -AppleLanguages '(es)' -AppleLocale es_ES
sleep 5
xcrun simctl io "$device" screenshot ui-preview/captures/principal-preview.png
xcrun simctl terminate "$device" com.gokuencinar.roothide3.uipreview
xcrun simctl launch "$device" com.gokuencinar.roothide3.uipreview --credits -AppleLanguages '(es)' -AppleLocale es_ES
sleep 5
xcrun simctl io "$device" screenshot ui-preview/captures/creditos-preview.png
python3 - "$runtime" <<'PY'
import json,os,sys
from pathlib import Path
Path('ui-preview/captures/provenance.json').write_text(json.dumps(dict(commit=os.environ['GITHUB_SHA'],runtime=sys.argv[1],kind='Isolated UIKit UI preview',original_components=['DOCreditsCell','DOHeaderCell','DOHeaderView','DOGlobalAppearance','DOActionMenuView','DOActionMenuButton','DOTheme','DOThemeManager'],simulated=['controller composition','device compatibility','all actions'],jailbreak_code_linked=False,installed_device_ipa=False),indent=2))
PY
cp tools/ui-preview/README.md ui-preview/captures/README.md
