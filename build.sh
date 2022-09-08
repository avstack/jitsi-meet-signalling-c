#!/bin/bash -e

mkdir -p tmp out/darwin out/ios

cargo build --release --target=aarch64-apple-darwin
cp target/aarch64-apple-darwin/release/libjitsi_meet_signalling_c.dylib tmp/libjitsi_meet_signalling_c_darwin_aarch64.dylib

cargo build --release --target=x86_64-apple-darwin
cp target/x86_64-apple-darwin/release/libjitsi_meet_signalling_c.dylib tmp/libjitsi_meet_signalling_c_darwin_x86_64.dylib

lipo -create -output out/darwin/libjitsi_meet_signalling_c.dylib tmp/libjitsi_meet_signalling_c_darwin_aarch64.dylib tmp/libjitsi_meet_signalling_c_darwin_x86_64.dylib

cargo build --release --target=aarch64-apple-ios
cp target/aarch64-apple-ios/release/libjitsi_meet_signalling_c.a out/ios/libjitsi_meet_signalling_c.a
