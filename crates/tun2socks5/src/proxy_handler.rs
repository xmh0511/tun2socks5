use crate::{
    directions::{IncomingDataEvent, OutgoingDataEvent, OutgoingDirection},
    session_info::SessionInfo,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

#[async_trait::async_trait]
pub(crate) trait ProxyHandler: Send + Sync {
    fn get_session_info(&self) -> SessionInfo;
    async fn push_data(&mut self, event: IncomingDataEvent<'_>) -> std::io::Result<()>;
    fn consume_data(&mut self, dir: OutgoingDirection, size: usize);
    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent;
    fn connection_established(&self) -> bool;
    fn data_len(&self, dir: OutgoingDirection) -> usize;
    fn reset_connection(&self) -> bool;
    fn get_udp_associate(&self) -> Option<SocketAddr>;
}

#[async_trait::async_trait]
pub(crate) trait ProxyHandlerManager: Send + Sync {
    async fn new_proxy_handler(&self, info: SessionInfo, udp_associate: bool) -> std::io::Result<Arc<Mutex<dyn ProxyHandler>>>;
    fn get_server_addr(&self) -> SocketAddr;
}
