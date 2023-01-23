//! Select functionality from [assuan-socket.c].
//!
//! [assuan-socket.c]: https://github.com/gpg/libassuan/blob/master/src/assuan-socket.c

use std::path::Path;

use crate::Result;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) type IpcStream = tokio::net::TcpStream;
#[cfg(unix)]
pub(crate) type IpcStream = tokio::net::UnixStream;

/// Connects to a local socket, returning a Tokio-enabled async connection.
///
/// Supports regular local domain sockets under Unix-like systems and
/// either Cygwin or libassuan's socket emulation on Windows.
///
/// # Panic
///
/// This function panics if not called from within a Tokio runtime.
pub(crate) fn sock_connect(path: impl AsRef<Path>) -> Result<IpcStream> {
    platform! {
      unix => {
        let stream = std::os::unix::net::UnixStream::connect(path)?;
        stream.set_nonblocking(true)?;
        Ok(tokio::net::UnixStream::from_std(stream)?)
      },
      windows => {
        use std::io::{Write, Read};
        use std::net::{Ipv4Addr, TcpStream};

        use windows::{
            read_port_and_nonce,
            Rendezvous,
            UdsEmulation,
        };

        let rendezvous = read_port_and_nonce(path.as_ref())?;
        let Rendezvous { port, uds_emulation, nonce } = rendezvous;

        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))?;
        stream.set_nodelay(true)?;

        // Authorize ourselves with nonce read from the file
        stream.write(&nonce)?;

        if let UdsEmulation::Cygwin = uds_emulation {
            // The client sends the nonce back - not useful. Do a dummy read
            stream.read_exact(&mut [0u8; 16])?;

            // Send our credentials as expected by libassuan:
            // [  pid  |uid|gid] (8 bytes)
            // [_|_|_|_|_|_|_|_]
            let mut creds = [0u8; 8]; // uid = gid = 0
            creds[..4].copy_from_slice(&std::process::id().to_ne_bytes());
            stream.write_all(&creds)?;
            // FIXME: libassuan in theory reads only 8 bytes here, but
            // somehow 12 have to be written for the server to progress (tested
            // on mingw-x86_64-gnupg).
            // My bet is that mingw socket API does that transparently instead
            // and expects to read an actual `ucred` struct (socket.h) which is
            // three `__u32`s.
            // Here, neither client nor server uses it, so just send dummy bytes
            stream.write_all(&[0u8; 4])?;

            // Receive back credentials. We don't need them.
            stream.read_exact(&mut [0u8; 12])?;
        }

        stream.set_nonblocking(true)?;
        Ok(tokio::net::TcpStream::from_std(stream)?)
      },
    }
}
