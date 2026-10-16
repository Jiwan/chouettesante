// Mirrors Session.field_0x740 in libIOTCAPIs.so: the main connection state
// machine, as a typestate.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use tracing::{debug, warn};

use super::{
    records::{
        make_hello_server, make_record_send_master_handshake,
        make_record_send_p2p_init_handshake_req, make_record_send_p2p_keep_alive, parse,
    },
    session::{ParseOutcome, PeerState, ServerEntry, SessionCore},
};

#[derive(Debug)]
pub(super) enum ConnectionAction {
    Send { data: Vec<u8>, to: SocketAddr },
    Finished,
}

impl ConnectionAction {
    fn data(&self) -> &[u8] {
        match self {
            ConnectionAction::Send { data, .. } => data,
            ConnectionAction::Finished => &[],
        }
    }
}

// No connection started yet.
pub(super) struct Idle {
    core: SessionCore,
}

// Master handshake records resent to every master address on each tick
// until one answers (state 1).
pub(super) struct MasterHandshake {
    core: SessionCore,
    addrs: Vec<SocketAddr>,
    deadline: Instant,
}

// P2P init handshake requests resent to every candidate on each tick
// (states 4-5). The binary's states 2-4 (hello/pre-session wait) are folded
// into the MasterHandshake -> P2PHandshaking transition since we do not
// implement the pre-session wait.
pub(super) struct P2PHandshaking {
    core: SessionCore,
    servers: Vec<ServerEntry>,
    deadline: Instant,
    offline_warning_sent: bool,
}

// One peer carries the session; unencrypted keepalives at the
// server-provided interval (state 6).
pub(super) struct Connected {
    core: SessionCore,
    peer: SocketAddr,
    record_sid: u32,
    keepalive_period: Duration,
    next_keepalive: Instant,
    // Observe the connected session for 30s for now; becomes "forever"
    // once the data channels are implemented.
    observe_until: Instant,
}

pub(super) enum Session {
    Idle(Idle),
    MasterHandshake(MasterHandshake),
    P2PHandshaking(P2PHandshaking),
    Connected(Connected),
}

impl Idle {
    // Starts the connection machine: the master handshake will be crafted
    // and resent to every address on each tick until one answers.
    fn start_connection(self, master_addrs: Vec<SocketAddr>) -> MasterHandshake {
        MasterHandshake {
            core: self.core,
            addrs: master_addrs,
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }

    fn on_tick(&mut self) -> Result<Vec<ConnectionAction>> {
        Ok(vec![])
    }

    // Datagrams still update the peers and the public address, but an
    // idle session never transitions.
    fn on_datagram(
        mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(Session, Vec<ConnectionAction>)> {
        let outcome = parse(data, Some(&self.core), Some(from))?;
        self.core.apply_peer_outcome(&outcome, from);

        Ok((Session::Idle(self), vec![]))
    }
}

impl MasterHandshake {
    fn on_tick(&mut self) -> Result<Vec<ConnectionAction>> {
        let now = Instant::now();

        if now > self.deadline {
            bail!("Timed out waiting for the master handshake response");
        }

        let data = make_record_send_master_handshake(&self.core)?;

        Ok(self
            .addrs
            .iter()
            .map(|to| ConnectionAction::Send {
                data: data.clone(),
                to: *to,
            })
            .collect())
    }

    fn on_datagram(
        mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(Session, Vec<ConnectionAction>)> {
        let outcome = parse(data, Some(&self.core), Some(from))?;
        self.core.apply_peer_outcome(&outcome, from);

        match outcome {
            ParseOutcome::ServerList(servers) => {
                let (state, actions) = self.enter_p2p_handshaking(servers)?;
                Ok((Session::P2PHandshaking(state), actions))
            }
            _ => Ok((Session::MasterHandshake(self), vec![])),
        }
    }

    // MasterHandshake -> P2PHandshaking: the entry actions send a hello and
    // a handshake request to every candidate. Crafting the handshake
    // records also creates the peers, each starting in
    // AwaitingHandshakeResp.
    fn enter_p2p_handshaking(
        self,
        servers: Vec<ServerEntry>,
    ) -> Result<(P2PHandshaking, Vec<ConnectionAction>)> {
        debug!("Master returned {} P2P server candidates", servers.len());

        let addrs: Vec<SocketAddr> = servers
            .iter()
            .map(|server| SocketAddr::from((server.ip_address, server.port)))
            .collect();

        // Entry actions: one hello packet per candidate (the same packet,
        // so it is crafted once and cloned), then one handshake record per
        // candidate, which also creates the peers.
        let mut core = self.core;
        let hello_packet = make_hello_server(&core)?;
        let mut actions: Vec<ConnectionAction> = addrs
            .iter()
            .map(|to| ConnectionAction::Send {
                data: hello_packet.clone(),
                to: *to,
            })
            .collect();

        for (server, to) in servers.iter().zip(addrs) {
            actions.push(ConnectionAction::Send {
                data: make_record_send_p2p_init_handshake_req(&mut core, server)?,
                to,
            });
        }

        Ok((
            P2PHandshaking {
                core,
                servers,
                deadline: Instant::now() + Duration::from_secs(60),
                offline_warning_sent: false,
            },
            actions,
        ))
    }
}

impl P2PHandshaking {
    fn on_tick(&mut self) -> Result<Vec<ConnectionAction>> {
        let now = Instant::now();

        if now > self.deadline {
            bail!("Timed out waiting for the P2P handshake response");
        }

        // One record per candidate; this also creates the peers on the
        // first pass (their credentials are cached afterwards). The
        // servers and the crafting core are disjoint fields, so both may
        // be borrowed at once.
        self.servers
            .iter()
            .map(|server| {
                Ok(ConnectionAction::Send {
                    data: make_record_send_p2p_init_handshake_req(&mut self.core, server)?,
                    to: SocketAddr::from((server.ip_address, server.port)),
                })
            })
            .collect()
    }

    fn on_datagram(
        mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(Session, Vec<ConnectionAction>)> {
        let outcome = parse(data, Some(&self.core), Some(from))?;
        self.core.apply_peer_outcome(&outcome, from);

        match outcome {
            // A master response that arrives once the handshakes are
            // already running is a duplicate: no way back.
            ParseOutcome::ServerList(_) => {
                debug!("Ignoring a duplicate master handshake response");
                Ok((Session::P2PHandshaking(self), vec![]))
            }
            ParseOutcome::HandshakeResp {
                record_sid,
                keepalive_interval,
            } => Ok((
                self.enter_connected(from, record_sid, keepalive_interval),
                vec![],
            )),
            ParseOutcome::DeviceStatus { .. } => {
                // One aggregated warning once every peer reports the device
                // as offline there.
                if self.core.device_offline_everywhere() && !self.offline_warning_sent {
                    self.offline_warning_sent = true;
                    warn!(
                        "The device is reported offline by all {} P2P servers",
                        self.core.peers.len()
                    );
                }

                Ok((Session::P2PHandshaking(self), vec![]))
            }
            _ => Ok((Session::P2PHandshaking(self), vec![])),
        }
    }

    // P2PHandshaking -> Connected: this peer carries the session from now
    // on; keepalives start at the server-provided interval. The per-peer
    // machine must have promoted this peer already (by apply_peer_outcome
    // above); otherwise the session stays handshaking.
    fn enter_connected(
        self,
        peer: SocketAddr,
        record_sid: u32,
        keepalive_interval: u16,
    ) -> Session {
        if !matches!(
            self.core.peers.get(&peer).map(|p| &p.state),
            Some(PeerState::Connected { .. })
        ) {
            return Session::P2PHandshaking(self);
        }

        debug!("Connected to P2P server {}", peer);

        let keepalive_period = Duration::from_secs(keepalive_interval.max(1) as u64);
        let now = Instant::now();

        Session::Connected(Connected {
            core: self.core,
            peer,
            record_sid,
            keepalive_period,
            next_keepalive: now + keepalive_period,
            observe_until: now + Duration::from_secs(30),
        })
    }
}

impl Connected {
    fn on_tick(&mut self) -> Result<Vec<ConnectionAction>> {
        let now = Instant::now();

        if now > self.observe_until {
            return Ok(vec![ConnectionAction::Finished]);
        }

        if now >= self.next_keepalive {
            self.next_keepalive = now + self.keepalive_period;

            return Ok(vec![ConnectionAction::Send {
                data: make_record_send_p2p_keep_alive(self.record_sid)?,
                to: self.peer,
            }]);
        }

        Ok(vec![])
    }

    fn on_datagram(
        mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(Session, Vec<ConnectionAction>)> {
        let outcome = parse(data, Some(&self.core), Some(from))?;
        self.core.apply_peer_outcome(&outcome, from);

        Ok((Session::Connected(self), vec![]))
    }
}

macro_rules! state_dispatch {
    ($( $i:ident ),*) => {
        pub(super) fn on_tick(&mut self) -> Result<Vec<ConnectionAction>> {
            match self {
                $( Session::$i(state) => state.on_tick(), )*
            }
        }

        pub(super) fn on_datagram(
            self,
            data: &[u8],
            from: SocketAddr,
        ) -> Result<(Session, Vec<ConnectionAction>)> {
            match self {
                $( Session::$i(state) => state.on_datagram(data, from), )*
            }
        }
    };
}

impl Session {
    // A fresh session, not yet connected.
    pub(super) fn new(session_id: u32, uid: &str) -> Session {
        Session::Idle(Idle {
            core: SessionCore::new(session_id, uid),
        })
    }

    // Only an idle session can start connecting; any other state is a
    // driver bug, mirroring iotc_connect failing on an in-use session.
    pub(super) fn start_connection(self, master_addrs: Vec<SocketAddr>) -> Result<Session> {
        match self {
            Session::Idle(idle) => Ok(Session::MasterHandshake(
                idle.start_connection(master_addrs),
            )),
            _ => bail!("Only an idle session can start connecting"),
        }
    }

    state_dispatch!(Idle, MasterHandshake, P2PHandshaking, Connected);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};

    use crate::iotc::{constants, session::test_public_key};

    #[test]
    fn connection_state_machine_transitions_through_the_phases() {
        let core = SessionCore::new(1, "ABCDEFGHIJKLMNOPQRST");
        let session = Session::Idle(Idle { core });
        assert!(matches!(session, Session::Idle(_)));

        let master_addr = SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 10240));
        let mut session = session.start_connection(vec![master_addr]).unwrap();
        assert!(matches!(session, Session::MasterHandshake(_)));

        // On a tick, the machine crafts the master record last minute and
        // sends it to every master address.
        let actions = session.on_tick().unwrap();
        assert!(matches!(
            actions.as_slice(),
            [ConnectionAction::Send { ref to, .. }] if to == &master_addr
        ));
        assert_eq!(
            actions[0].data().len(),
            constants::RECORD_HEADER_SIZE + 0x100
        );

        // The master returned a server list: entry actions of the
        // P2PHandshaking state (hello + handshake to every candidate, peers
        // created).
        let entry = ServerEntry {
            ip_address: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            port: 3478,
            pub_key: test_public_key().unwrap(),
        };
        let peer_addr = SocketAddr::from((Ipv4Addr::new(5, 6, 7, 8), 3478));
        let Session::MasterHandshake(state) = session else {
            panic!("The session must be in the master handshake state");
        };
        let (state, actions) = state.enter_p2p_handshaking(vec![entry]).unwrap();
        let mut session = Session::P2PHandshaking(state);
        // One hello per candidate, then one handshake record per candidate.
        assert_eq!(actions.len(), 2);
        assert!(matches!(
            actions[0],
            ConnectionAction::Send { ref to, .. } if to == &peer_addr
        ));
        assert!(matches!(
            actions[1],
            ConnectionAction::Send { ref to, .. } if to == &peer_addr
        ));
        assert_eq!(actions[0].data().len(), 0x18);
        assert_eq!(
            actions[1].data().len(),
            constants::RECORD_HEADER_SIZE + 0xac
        );
        let Session::P2PHandshaking(state) = &session else {
            panic!("The session must be handshaking");
        };
        assert_eq!(state.core.peers.len(), 1);
        assert_eq!(
            state.core.peers[&peer_addr].state,
            PeerState::AwaitingHandshakeResp
        );

        // Each tick recrafts one handshake record per candidate.
        let actions = session.on_tick().unwrap();
        assert!(matches!(
            actions.as_slice(),
            [ConnectionAction::Send { ref to, .. }] if to == &peer_addr
        ));

        // A duplicate master response cannot even be expressed anymore:
        // only the MasterHandshake state knows how to enter P2P handshaking.

        // The handshake response is accepted: the per-peer machine promotes
        // the peer, then the main machine enters Connected with this peer
        // carrying the session and keepalives at the server-provided
        // interval.
        let Session::P2PHandshaking(mut state) = session else {
            panic!("The session must be handshaking");
        };
        state.core.apply_peer_outcome(
            &ParseOutcome::HandshakeResp {
                record_sid: 0xdeadbeef,
                keepalive_interval: 42,
            },
            peer_addr,
        );
        assert!(matches!(
            state.core.peers[&peer_addr].state,
            PeerState::Connected {
                record_sid: 0xdeadbeef,
                keepalive_interval: 42,
                ..
            }
        ));
        let mut session = state.enter_connected(peer_addr, 0xdeadbeef, 42);
        assert!(matches!(
            &session,
            Session::Connected(Connected {
                peer,
                record_sid,
                keepalive_period,
                ..
            }) if *peer == peer_addr && *record_sid == 0xdeadbeef && *keepalive_period == Duration::from_secs(42)
        ));

        // Keepalives are not due yet...
        assert!(session.on_tick().unwrap().is_empty());

        // ...then they are.
        if let Session::Connected(Connected { next_keepalive, .. }) = &mut session {
            *next_keepalive -= Duration::from_secs(60);
        }
        let actions = session.on_tick().unwrap();
        assert!(matches!(
            actions.as_slice(),
            [ConnectionAction::Send { ref to, ref data }] if to == &peer_addr && data.len() == 0x18
        ));
    }
}
