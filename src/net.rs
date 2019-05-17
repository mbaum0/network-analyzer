pub mod types {

  pub struct MacAddress {
    address: [u8; 6]
  }

  impl MacAddress {
      pub fn new(address: [u8; 6]) -> MacAddress {
        MacAddress {
          address
        }
      }

      pub fn as_string(&self) -> String {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
          self.address[0], self.address[1], self.address[2], self.address[3],
          self.address[4], self.address[5])
      }

      pub fn as_bytes(&self) -> &[u8] {
        &self.address
      }

      pub fn as_u64(&self) -> u64 {
        u64::from_be_bytes([0, 0, self.address[0], self.address[1], self.address[2],
          self.address[3], self.address[4], self.address[5]])
      }
  }

  pub struct IPv4Address {
    address: [u8; 4]
  }

  impl IPv4Address {
    pub fn new(address: [u8; 4]) -> IPv4Address {
      IPv4Address {
        address
      }
    }

    pub fn as_string(&self) -> String {
      format!("{}.{}.{}.{}", self.address[0], self.address[1], self.address[2], self.address[3])
    }

    pub fn as_bytes(&self) -> &[u8] {
      &self.address
    }

    pub fn as_u32(&self) -> u32 {
      u32::from_be_bytes([self.address[0], self.address[1], self.address[2], self.address[3]])
    }
  }

  pub struct EtherType {
    value: u16
  }

  impl EtherType {
    pub fn new(bytes: [u8; 2]) -> EtherType {
      EtherType {
        value: u16::from_be_bytes([bytes[0], bytes[1]])
      }
    }

    pub fn as_string(&self) -> String {
      // if value field is greater than 0x05DC (1500) this
      // is an Ethernet Version 2 frame. If less than 0x05DC,
      // this frame is IEEE 802.3 Ethernet frame.
      let eth2_cutoff = 0x05DC;
      
      if self.value < eth2_cutoff {
        return String::from("802.3");
      }

      match self.value {
      0x0800 => String::from("ipv4"),
      0x0806 => String::from("arp"),
      0x8100 => String::from("vlan"),
      0x86dd => String::from("ipv6"),
      0x8847 => String::from("mpls"),
           _ => String::from("")
      } 
    }
  }
}

pub mod frames {
  use super::types::{MacAddress, EtherType};

  pub struct EthernetFrame<'p> {
    dst_mac: MacAddress,
    src_mac: MacAddress,
    eth_type: EtherType,
    payload: &'p [u8]
  }

  impl<'p> EthernetFrame<'p> {
    pub fn new(bytes: &[u8]) -> EthernetFrame {
      EthernetFrame {
        dst_mac:  MacAddress::new([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]),
        src_mac:  MacAddress::new([bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11]]),
        eth_type: EtherType::new([bytes[12], bytes[13]]),
        payload:  &bytes[14..]
      }
    }

    pub fn as_string(&self) -> String {
      format!("ETHERNET: [{}] [{} -> {}]", self.eth_type.as_string(), self.src_mac.as_string(), self.dst_mac.as_string())
    }
  }
}