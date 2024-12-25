#!/usr/bin/env bash

set -e

echo "Generating SchemeBlock from Scheme"
sed 's/trait Scheme/trait SchemeBlock/' scheme.rs \
| sed 's/fn handle(\&mut self, packet: \&mut Packet)/fn handle(\&mut self, packet: \&Packet) -> Option<usize>/' \
| sed 's/packet.a = Error::mux(res);/res.transpose().map(Error::mux)/' \
| sed 's/\.map(|f| f\.bits())/\.map(|f| f.map(|f| f.bits()))/' \
| sed 's/\.map(|o| o as usize)/.map(|o| o.map(|o| o as usize))/' \
| sed 's/Ok(0)/Ok(Some(0))/g' \
| sed 's/Result<\([^>]\+\)>/Result<Option<\1>>/g' \
| sed 's/convert_to_this_scheme/convert_to_this_scheme_block/g' \
> scheme_block.rs
