#all: mktemp choma

#mktemp:
#	rm -rf .build-dir
#	mkdir .build-dir

#choma:
#	$(MAKE) -C ChOma TARGET=ios DISABLE_SIGNING=1 DYLIB_LDFLAGS="-install_name @loader_path/libchoma.dylib" $@

all: basebin.tar

# Parallelism is safe only after BOTH staging directories have been recreated.
# Individual components own distinct staged outputs; explicit prerequisites
# below serialize consumers of generated headers/libraries. In particular,
# trustcache and dyldhook/tar must wait for ALL of the parallel subprojects.
# Do not introduce a global .NOTPARALLEL: MachOMerger and independent BaseBin
# components would otherwise consume most of the build time sequentially.
staging: .build .include

subprojects: ChOma XPF MachOMerger opainject tweakprobe libjailbreak systemhook forkfix launchdhook hookd boomerang jbctl idownloadd watchdoghook rootlesshooks roothidehooks jailbreakd bootstrapper dopamine

ChOma: staging
	@python3 ../tools/apply_choma_fixes.py
	@$(MAKE) -C ChOma TARGET=ios DISABLE_SIGNING=1 DISABLE_TESTS=1 DYLIB_LDFLAGS="-install_name @loader_path/libchoma.dylib"
	@ldid -Cadhoc -s ChOma/output/ios/lib/libchoma.dylib
	@cp ChOma/output/ios/lib/libchoma.dylib .build
	@cp -r ChOma/output/ios/include/choma .include

XPF: staging ChOma
	@$(MAKE) -C XPF output/ios/libxpf.dylib CHOMA_PATH=../ChOma CHOMA_DYLIB_PATH="../.build"
	@ldid -Cadhoc -s XPF/output/ios/libxpf.dylib
	@cp XPF/output/ios/libxpf.dylib .build/libxpf.dylib
	@mkdir -p .include/xpf
	@cp XPF/src/xpf.h .include/xpf

MachOMerger: staging
	@$(MAKE) -C MachOMerger
	@cp MachOMerger/MachOMerger .build

opainject: staging
	$(MAKE) -C opainject
	@cp opainject/opainject .build

tweakprobe: staging
	$(MAKE) -C tweakprobe
	@cp tweakprobe/rh3tweakprobe .build

libjailbreak: staging ChOma
	$(MAKE) -C libjailbreak
	@cp libjailbreak/libjailbreak.dylib .build
	@mkdir -p .include/libjailbreak
	@cp libjailbreak/src/*.h .include/libjailbreak
	@mkdir -p .include/libjailbreak/roothider
	@cp libjailbreak/src/roothider/*.h .include/libjailbreak/roothider

systemhook: staging libjailbreak
	$(MAKE) -C systemhook
	@cp systemhook/systemhook.dylib .build

forkfix: staging libjailbreak systemhook
	$(MAKE) -C forkfix
	@cp forkfix/forkfix.dylib .build

launchdhook: staging libjailbreak
	$(MAKE) -C launchdhook
	@cp launchdhook/launchdhook.dylib .build

hookd: staging libjailbreak
	$(MAKE) -C hookd
	@cp hookd/hookd .build

boomerang: staging libjailbreak
	$(MAKE) -C boomerang
	@cp boomerang/boomerang .build

jbctl: staging libjailbreak
	$(MAKE) -C jbctl
	@cp jbctl/jbctl .build

idownloadd: staging libjailbreak
	$(MAKE) -C idownloadd
	@cp idownloadd/idownloadd .build

watchdoghook: staging libjailbreak
	$(MAKE) -C watchdoghook
	@cp watchdoghook/watchdoghook.dylib .build

rootlesshooks: staging libjailbreak
	$(MAKE) -C rootlesshooks
	@cp rootlesshooks/.theos/obj/rootlesshooks.dylib .build

# These RootHide components coexist with Dopamine 3's hookd and rootlesshooks;
# hiding is not activated unless the hidden bootstrap state is initialized.
roothidehooks: staging libjailbreak
	$(MAKE) -C roothidehooks
	@cp roothidehooks/.theos/obj/roothidehooks.dylib .build

jailbreakd: staging libjailbreak
	$(MAKE) -C jailbreakd
	@cp jailbreakd/jailbreakd .build

bootstrapper: staging libjailbreak
	$(MAKE) -C bootstrapper
	@cp bootstrapper/bootstrapper .build

dopamine: staging libjailbreak XPF ChOma
	$(MAKE) -C dopamine
	@cp dopamine/dopamine .build

.build:
	rm -rf .build
	mkdir -p .build
	cp -r _external/basebin/* .build
	cp _external/basebin/.version .build

.include:
	rm -rf .include
	mkdir -p .include
	cp -r _external/include/* .include
# If the SDK already ships XPC (it does so in iOS 17.4+), remove the local copy of it
ifneq (,$(wildcard $(shell xcrun --sdk iphoneos --show-sdk-path)/usr/include/xpc.modulemap))
	rm -rf .include/xpc
endif

basebin.tc: subprojects
	trustcache create .build/basebin.tc .build
	cp .build/basebin.tc basebin.tc

# dyldhook dylibs do not need to be added to the basebin trustcache
dyldhook: basebin.tc
	$(MAKE) -C dyldhook
	@cp dyldhook/*.dylib .build

basebin.tar: basebin.tc dyldhook
	@find ./.build -name ".DS_Store" -delete
	@DYLD_FALLBACK_LIBRARY_PATH="." ./tar --transform "s/^.build/basebin/" -cvf "basebin.tar" ".build" --owner=0 --group=0

clean:
	@$(MAKE) -C ChOma $@
	@$(MAKE) -C XPF $@
	@$(MAKE) -C MachOMerger $@
	@$(MAKE) -C opainject $@
	@$(MAKE) -C tweakprobe $@
	@$(MAKE) -C libjailbreak $@
	@$(MAKE) -C systemhook $@
	@$(MAKE) -C forkfix $@
	@$(MAKE) -C launchdhook $@
	@$(MAKE) -C boomerang $@
	@$(MAKE) -C jbctl $@
	@$(MAKE) -C idownloadd $@
	@$(MAKE) -C watchdoghook $@
	@$(MAKE) -C rootlesshooks $@
	@$(MAKE) -C roothidehooks $@
	@$(MAKE) -C jailbreakd $@
	@$(MAKE) -C bootstrapper $@
	@$(MAKE) -C dyldhook $@
	@$(MAKE) -C dopamine $@
	@$(MAKE) -C hookd $@
	@rm -rf .build
	@rm -rf .include
	@rm -rf basebin.tar
	@rm -rf basebin.tc

.PHONY: clean staging .build .include ChOma XPF MachOMerger opainject tweakprobe libjailbreak systemhook forkfix launchdhook hookd boomerang jbctl idownloadd watchdoghook rootlesshooks roothidehooks jailbreakd bootstrapper basebin.tc dyldhook basebin.tar
