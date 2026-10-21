export NIGHTLY ?= 0

export BUILD_STANDALONE ?= 0

ifeq ($(NIGHTLY), 1)
export COMMIT_HASH = $(shell git rev-parse HEAD)
endif

ifeq ($(BUILD_STANDALONE), 1)
export BUILD_STANDALONE = 1
endif

# The IPA bundles BaseBin and the three generated dependency packages.
# Keep those producer/consumer edges explicit, but build the independent
# Application and Standalone artifacts concurrently with GNU Make's jobserver.
# A recipe with four sequential $(MAKE) calls would ignore the outer -j.
all: application standalone

basebin:
	@$(MAKE) -C BaseBin

packages: basebin
	@$(MAKE) -C Packages

application: packages
	@$(MAKE) -C Application

standalone: packages
	@$(MAKE) -C Standalone

clean:
	@$(MAKE) -C BaseBin clean
	@$(MAKE) -C Packages clean
	@$(MAKE) -C Application clean
	@$(MAKE) -C Standalone clean

update: all
	ssh $(DEVICE) "rm -rf /var/mobile/Documents/Dopamine.tipa"
	scp -C ./Application/Dopamine.tipa "$(DEVICE):/var/mobile/Documents/Dopamine.tipa"
	ssh $(DEVICE) "/var/jb/basebin/jbctl update tipa /var/mobile/Documents/Dopamine.tipa"

update-basebin: all
	ssh $(DEVICE) "rm -rf /var/mobile/Documents/basebin.tar"
	scp -C ./BaseBin/basebin.tar "$(DEVICE):/var/mobile/Documents/basebin.tar"
	ssh $(DEVICE) "/var/jb/basebin/jbctl update basebin /var/mobile/Documents/basebin.tar"

.PHONY: all basebin packages application standalone update clean
