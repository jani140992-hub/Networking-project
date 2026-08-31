"""Unit tests for BGP-4 Finite State Machine."""
import unittest
from netsphere.protocols.l7.bgp_fsm import BGPPeerSession, BGPState, BGPEvent


class TestBGPFSM(unittest.TestCase):
    def test_bgp_full_session_establishment(self):
        peer = BGPPeerSession(peer_ip="198.51.100.1", remote_as=65001, local_as=65000)
        self.assertEqual(peer.state, BGPState.IDLE)

        peer.process_event(BGPEvent.MANUAL_START)
        self.assertEqual(peer.state, BGPState.CONNECT)

        peer.process_event(BGPEvent.TCP_CONNECTION_CONFIRMED)
        self.assertEqual(peer.state, BGPState.OPENSENT)

        peer.process_event(BGPEvent.BGP_OPEN_RECEIVED)
        self.assertEqual(peer.state, BGPState.OPENCONFIRM)

        peer.process_event(BGPEvent.BGP_KEEPALIVE_RECEIVED)
        self.assertEqual(peer.state, BGPState.ESTABLISHED)

    def test_bgp_teardown(self):
        peer = BGPPeerSession(peer_ip="198.51.100.1", remote_as=65001, local_as=65000)
        peer.process_event(BGPEvent.MANUAL_START)
        peer.process_event(BGPEvent.TCP_CONNECTION_CONFIRMED)
        peer.process_event(BGPEvent.BGP_OPEN_RECEIVED)
        peer.process_event(BGPEvent.BGP_KEEPALIVE_RECEIVED)
        self.assertEqual(peer.state, BGPState.ESTABLISHED)

        peer.process_event(BGPEvent.NOTIFICATION_RECEIVED)
        self.assertEqual(peer.state, BGPState.IDLE)


if __name__ == "__main__":
    unittest.main()
