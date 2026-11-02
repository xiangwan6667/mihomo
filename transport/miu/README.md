# Miu transport

This directory contains the root `miu` package from https://github.com/MiuProtocol/Miu at commit `08dbc75484abd9249c4a9534a43458aee144dbe6`. The MIT license is in `LICENSE`. The protocol code is copied here to retain mihomo's Go 1.20 compatibility without upgrading its dependencies.

The copied unit tests use the local `testdata` directory, and one use of the Go 1.21 `min` built-in is written out for Go 1.20 compatibility. The protocol implementation files are otherwise unchanged.
