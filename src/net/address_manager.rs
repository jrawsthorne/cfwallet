use bitcoin::{network::constants::ServiceFlags, secp256k1::rand::prelude::*};
use std::{collections::HashSet, net::SocketAddr};

#[derive(Debug, Clone, Default)]
pub struct AddressManager {
    /// All addresses seen from `addr` announcements and dns seeds
    seen: HashSet<SocketAddr>,
    /// Addresses not yet retrieved
    addrs: Vec<(SocketAddr, ServiceFlags)>,
}

impl AddressManager {
    /// Create an empty address manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an address manager with already seeded addresses (e.g. from dns seeds or disk)
    pub fn with_addrs(addrs: Vec<SocketAddr>) -> Self {
        let mut address_manager = Self::new();
        for addr in addrs {
            address_manager.add(addr, ServiceFlags::NONE);
        }
        address_manager
    }

    /// Get an address for a peer that signalled support for sending full blocks
    pub fn get_full_block_addr(&mut self) -> Option<SocketAddr> {
        self.get_addr_with_services(ServiceFlags::NETWORK)
    }

    /// Get an address for a peer that signalled support for sending compact block filters
    pub fn get_compact_filter_addr(&mut self) -> Option<SocketAddr> {
        self.get_addr_with_services(ServiceFlags::COMPACT_FILTERS)
    }

    /// Get an address with no constrants on services
    pub fn get_addr(&mut self) -> Option<SocketAddr> {
        self.addrs.pop().map(|(addr, _)| addr)
    }

    /// Get an address for a peer that signals certain service flags
    pub fn get_addr_with_services(&mut self, services: ServiceFlags) -> Option<SocketAddr> {
        let required_services = services | ServiceFlags::WITNESS;

        let pos = self
            .addrs
            .iter()
            .position(|(_, services)| services.has(required_services))?;

        let (addr, _) = self.addrs.remove(pos);

        Some(addr)
    }

    /// Add an address with certain service flags, will update service flags if address already present
    pub fn add(&mut self, addr: SocketAddr, services: ServiceFlags) {
        if self.seen.insert(addr) {
            self.addrs.push((addr, services));
            self.addrs.shuffle(&mut thread_rng())
        }
    }
}
