use std::net::{Shutdown, TcpStream};

use super::effects::{NetworkOp, NetworkReply};
use super::shell::RealShell;

impl RealShell<'_> {
    pub(super) fn handle_network(&mut self, operation: NetworkOp) -> Result<NetworkReply, String> {
        match operation {
            NetworkOp::BindListener { addr } => {
                let listener =
                    std::net::TcpListener::bind(addr).map_err(|err| format!("listen: {err}"))?;
                let local_addr = listener
                    .local_addr()
                    .map_err(|err| format!("listener local addr: {err}"))?;
                let listener_id = self.next_listener_id;
                self.next_listener_id = self.next_listener_id.saturating_add(1);
                self.listeners.insert(listener_id, listener);
                Ok(NetworkReply::ListenerBound {
                    listener_id,
                    local_addr,
                })
            }
            NetworkOp::AcceptStream { listener_id } => {
                let listener = self
                    .listeners
                    .get(&listener_id)
                    .ok_or_else(|| format!("unknown listener id {listener_id}"))?;
                let (stream, peer_addr) = listener
                    .accept()
                    .map_err(|err| format!("accept tcp stream: {err}"))?;
                stream
                    .set_nodelay(true)
                    .map_err(|err| format!("set stream nodelay: {err}"))?;
                let stream_id = self.next_stream_id;
                self.next_stream_id = self.next_stream_id.saturating_add(1);
                self.streams.insert(stream_id, stream);
                Ok(NetworkReply::StreamAccepted {
                    stream_id,
                    peer_addr,
                })
            }
            NetworkOp::OpenStream { addr } => {
                let stream = crate::protocol::network::connect(addr)
                    .map_err(|err| format!("open tcp stream: {err}"))?;
                let stream_id = self.next_stream_id;
                self.next_stream_id = self.next_stream_id.saturating_add(1);
                self.streams.insert(stream_id, stream);
                Ok(NetworkReply::StreamOpened { stream_id })
            }
            NetworkOp::WriteFrames { stream_id, frames } => {
                let stream = self.stream(stream_id)?;
                crate::protocol::network::write_frames(stream, frames)?;
                Ok(NetworkReply::FramesWritten)
            }
            NetworkOp::ReadFrame { stream_id } => {
                let read = {
                    let stream = self.stream(stream_id)?;
                    crate::protocol::network::read_frame(stream)
                };
                match read {
                    Ok(bytes) => Ok(NetworkReply::FrameRead(bytes)),
                    Err(err) if is_stream_closed(&err) => {
                        self.streams.remove(&stream_id);
                        Ok(NetworkReply::StreamClosed)
                    }
                    Err(err) => Err(format!("read frame: {err}")),
                }
            }
            NetworkOp::ShutdownWrite { stream_id } => {
                let stream = self.stream(stream_id)?;
                stream
                    .shutdown(Shutdown::Write)
                    .map_err(|err| format!("shutdown stream write: {err}"))?;
                Ok(NetworkReply::WriteShutdown)
            }
        }
    }

    fn stream(&mut self, stream_id: u64) -> Result<&mut TcpStream, String> {
        self.streams
            .get_mut(&stream_id)
            .ok_or_else(|| format!("unknown stream id {stream_id}"))
    }
}

fn is_stream_closed(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}
