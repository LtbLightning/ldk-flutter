.DEFAULT_GOAL := help
PROJECTNAME=$(shell basename "$(PWD)")
SOURCES=$(sort $(wildcard ./src/*.rs ./src/**/*.rs))

OS_NAME=$(shell uname | tr '[:upper:]' '[:lower:]')
BINPATH = $(ANDROID_NDK_HOME)/25.0.8775105/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin

ANDROID_AARCH64_LINKER=$(BINPATH)/aarch64-linux-android29-clang
ANDROID_AARCH64_AR=$(BINPATH)/llvm-ar
ANDROID_ARMV7_LINKER=$(BINPATH)/armv7a-linux-androideabi29-clang
ANDROID_ARM7_AR=$(BINPATH)/llvm-ar
ANDROID_I686_LINKER=$(BINPATH)/i686-linux-android29-clang
ANDROID_I686_AR=$(BINPATH)/llvm-ar
ANDROID_X86_64_LINKER=$(BINPATH)/x86_64-linux-android29-clang
ANDROID_X86_64_AR=$(BINPATH)/llvm-ar

SHELL := /bin/bash

# ##############################################################################
# # GENERAL
# ##############################################################################

.PHONY: help
help: makefile
	@echo
	@echo " Available actions in "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

## init: Install missing dependencies.
.PHONY: init
init:

	rustup target add aarch64-apple-ios x86_64-apple-ios
	rustup target add aarch64-apple-darwin x86_64-apple-darwin
	#rustup target add armv7-apple-ios armv7s-apple-ios i386-apple-ios ## deprecated
	rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
	@if [ $$(uname) == "Darwin" ] ; then cargo install cargo-lipo ; fi
	cargo install flutter_rust_bridge_codegen


