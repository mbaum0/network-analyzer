extern crate pcap;

use netproto::{frames};

//use pcap::{Device, Capture};
use pcap::Capture;

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


fn capture_packets(dev_name : &str) {
  let mut cap = Capture::from_device(dev_name).unwrap()
                    .promisc(true)
                    .snaplen(5000)
                    .open().unwrap();
 


  while let Ok(packet) = cap.next() {
    let data = packet.data;
    let eth_frame = frames::EthernetFrame::new(data);
    println!("\n{}", eth_frame.as_string());

    if eth_frame.eth_type().as_string() == "IPv4" {
      let ipv4_frame = frames::IPv4Frame::new(eth_frame.payload());
      println!("    {}", ipv4_frame.as_string());
    }
    else if eth_frame.eth_type().as_string() == "IPv6" {
      let ipv6_frame = frames::IPv6Frame::new(eth_frame.payload());
      println!("    {}", ipv6_frame.as_string());
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
