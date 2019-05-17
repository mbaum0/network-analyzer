extern crate pcap;

mod net;
use net::{frames};

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

    
    println!("{}", eth_frame.as_string());
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
