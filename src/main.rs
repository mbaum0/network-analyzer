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
    payload:  &packet[14..]
  }
}

struct ArpFrame<'mac, 'proto> {
  hardware_type: u16,
  protocol_type: u16,
  mac_address_length: u8,
  protocol_address_length: u8,
  op_code: u16,
  src_mac: &'mac [u8],
  src_protocol_address: &'proto [u8],
  target_mac_address: &'mac [u8],
  target_protocol_address: &'proto [u8]  
}

fn build_arp_frame(packet: &[u8]) -> ArpFrame {
  let mac_address_length = u8::from_be_bytes([packet[4]]);
  let mac_address_length_usize = usize::from(mac_address_length);
  let protocol_address_length = u8::from_be_bytes([packet[5]]);
  let protocol_address_length_usize = usize::from(protocol_address_length);

  let src_mac_index = 8 + mac_address_length_usize;
  let src_protocol_address_index = src_mac_index + protocol_address_length_usize;
  let target_mac_address_index = src_protocol_address_index + mac_address_length_usize;
  let target_protocol_address_index = target_mac_address_index + protocol_address_length_usize;

  ArpFrame {
    hardware_type: u16::from_be_bytes([packet[0], packet[1]]),
    protocol_type: u16::from_be_bytes([packet[2], packet[3]]),
    mac_address_length: mac_address_length,
    protocol_address_length: protocol_address_length,
    op_code: u16::from_be_bytes([packet[6], packet[7]]),
    src_mac: &packet[8..src_mac_index],
    src_protocol_address: &packet[src_mac_index..src_protocol_address_index],
    target_mac_address: &packet[src_protocol_address_index..target_mac_address_index],
    target_protocol_address: &packet[target_mac_address_index..target_protocol_address_index],
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

    let eth_type_name = get_ether_type_name(eth_frame.eth_type);
    let src_mac_str = get_mac_str(eth_frame.src_mac);
    let dst_mac_str = get_mac_str(eth_frame.dst_mac);
    
    println!("[{:?}] {:x?} -> {:x?}", eth_type_name, src_mac_str, dst_mac_str);

    if eth_type_name == "arp" {
      let arp_frame = build_arp_frame(eth_frame.payload);

      let arp_src_mac = arp_frame.src_mac;
      let arp_src_protocol_address = arp_frame.src_protocol_address;
      let arp_op_code = arp_frame.op_code;

      println!("\t[arp: {:?}] src mac: {:x?} src proto: {:?}", arp_op_code, arp_src_mac, arp_src_protocol_address);
    }
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
