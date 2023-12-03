use crate::{
    directions::{Direction, IncomingDataEvent, OutgoingDataEvent, OutgoingDirection},
    session_info::SessionInfo,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

pub(crate) trait ProxyHandler {
    fn get_connection_info(&self) -> SessionInfo;
    fn push_data(&mut self, event: IncomingDataEvent<'_>) -> std::io::Result<()>;
    fn consume_data(&mut self, dir: OutgoingDirection, size: usize);
    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent;
    fn connection_established(&self) -> bool;
    fn data_len(&self, dir: Direction) -> usize;
    fn reset_connection(&self) -> bool;
    fn get_udp_associate(&self) -> Option<SocketAddr>;
}

pub(crate) trait ConnectionManager {
    fn new_proxy_handler(&self, info: SessionInfo, udp_associate: bool) -> std::io::Result<Arc<Mutex<dyn ProxyHandler + Send + Sync>>>;
    fn get_server_addr(&self) -> SocketAddr;
}
