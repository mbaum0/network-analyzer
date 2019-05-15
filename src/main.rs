extern crate pcap;

//use pcap::{Device, Capture};
use pcap::Capture;

struct EthernetFrame<'p> {
  dst_mac: [u8; 6],
  src_mac: [u8; 6],
  eth_type: u16,
  payload: &'p [u8],
}

fn build_ethernet_frame(packet: &[u8]) -> EthernetFrame {
  EthernetFrame {
    dst_mac:  [packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]],
    src_mac:  [packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]],
    eth_type: u16::from_be_bytes([packet[12], packet[13]]),
    payload:  &packet[4..]
  }
}

fn main() {
  //let devices = Device::list();

  //match devices {
  //  Ok(vec_devices) => {
  //    print_available_devices(&vec_devices);
  //    std::process::exit(0);
  //  }
  //  Err(_) => {
  //    println!("No devices found...");
  //    std::process::exit(0);
  //  }
  //}

    capture_packets("wlp61s0");
}

// Returns a String representaion of the EtherType given
// a value
fn get_ether_type_name(eth_type : u16) -> String {
  
  // if eth_type field is greater than 0x05DC (1500) this
  // is an Ethernet Version 2 frame. If less than 0x05DC,
  // this frame is IEEE 802.3 Ethernet frame.
  let eth2_cutoff = 0x05DC;
  
  if eth_type < eth2_cutoff {
    return String::from("802.3");
  }

  match eth_type {
    0x0800 => String::from("ipv4"),
    0x0806 => String::from("arp"),
    0x8100 => String::from("vlan"),
    0x86dd => String::from("ipv6"),
    0x8847 => String::from("mpls"),
         _ => String::from(""),
  } 
}

fn get_mac_str(addr : [u8;6]) -> String {
  format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
}

fn capture_packets(dev_name : &str) {
  let mut cap = Capture::from_device(dev_name).unwrap()
                    .promisc(true)
                    .snaplen(5000)
                    .open().unwrap();
 


  while let Ok(packet) = cap.next() {
    let data = packet.data;

    let eth_frame = build_ethernet_frame(data);
    
    println!("[{:?}] {:x?} -> {:x?}", get_ether_type_name(eth_frame.eth_type), get_mac_str(eth_frame.src_mac), get_mac_str(eth_frame.dst_mac));
  }
}

//fn print_available_devices<'a> (vec_devices : &'a Vec<Device>){
//  println!("-available devices:",);
//  for device in vec_devices {
//    match device {
//      _ => println!("  * Device {:?} : {:?}", device.name, device.desc),
//    }
//  }
//}
