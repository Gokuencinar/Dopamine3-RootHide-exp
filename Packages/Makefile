# Each package owns its own staging directory. GNU Make can build these
# packages in parallel after BaseBin/libjailbreak headers and dylibs exist.
all: libkrw-provider libroot basebin-link

libkrw-provider:
	@$(MAKE) -C libkrw-provider package

libroot:
	@$(MAKE) -C libroot package

basebin-link:
	@$(MAKE) -C basebin-link package

clean:
	@$(MAKE) -C libkrw-provider clean
	@$(MAKE) -C libroot clean
	@$(MAKE) -C basebin-link clean

.PHONY: all libkrw-provider libroot basebin-link clean
