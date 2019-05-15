cargo build --release
sudo setcap cap_net_admin=eip target/release/network-analyzer
sudo setcap cap_net_raw=eip target/release/network-analyzer
./target/release/network-analyzer
