cargo build --release
sudo setcap cap_net_admin=eip target/release/dns-feed
sudo setcap cap_net_raw=eip target/release/dns-feed
./target/release/dns-feed
