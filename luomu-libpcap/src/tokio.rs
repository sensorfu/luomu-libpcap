//! Tokio support for libpcap

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::stream::Stream;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task;

use crate::functions as libpcap;
use crate::{Error, OwnedPacket};

/// Asynchronous Capture
///
/// This type uses Tokio's blocking task to run a libpcap capture loop.
#[derive(Debug)]
pub struct AsyncCapture {
    rx: mpsc::UnboundedReceiver<crate::Result<OwnedPacket>>,
}

impl AsyncCapture {
    /// Construct new packet capture instance.
    pub fn new(pcap: crate::Pcap) -> crate::Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        task::spawn_blocking(|| capture_loop(pcap, tx));
        Ok(Self { rx })
    }
}

impl Future for AsyncCapture {
    type Output = crate::Result<OwnedPacket>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(value)) => Poll::Ready(value),
            Poll::Ready(None) => Poll::Ready(Err(Error::Break)),
        }
    }
}

impl Stream for AsyncCapture {
    type Item = crate::Result<OwnedPacket>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll(cx).map(Option::Some)
    }
}

fn capture_loop(pcap: crate::Pcap, tx: UnboundedSender<crate::Result<OwnedPacket>>) {
    loop {
        match next_packet(&pcap) {
            Poll::Pending => continue,
            Poll::Ready(ret) => {
                let is_err = ret.is_err();
                if tx.send(ret).is_err() {
                    return;
                }
                if is_err {
                    return;
                }
            }
        }
    }
}

fn next_packet(pcap: &crate::Pcap) -> Poll<crate::Result<OwnedPacket>> {
    match libpcap::pcap_next_ex(&pcap.pcap_t) {
        Ok(p) => Poll::Ready(Ok(p.to_owned())),
        Err(Error::Timeout) => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}
