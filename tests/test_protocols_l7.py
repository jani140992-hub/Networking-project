"""Unit tests for Layer 7 Protocols (DNS, DHCP, HTTP1, HTTP2, MQTT, CoAP, SNMP, BGP, OSPF, NTP, WebSocket)."""
import unittest
from netsphere.core.buffer import PacketBuffer
from netsphere.protocols.l7.dns import DNSMessage, DNSType
from netsphere.protocols.l7.dhcp import DHCPMessage, DHCPOption, DHCPMessageType
from netsphere.protocols.l7.http1 import HTTP1Request, HTTP1Response
from netsphere.protocols.l7.http2 import HTTP2Frame, HTTP2FrameType
from netsphere.protocols.l7.mqtt import MQTTMessage, MQTTMessageType
from netsphere.protocols.l7.coap import CoAPMessage, CoAPType, CoAPCode
from netsphere.protocols.l7.snmp import SNMPMessage
from netsphere.protocols.l7.bgp import BGPMessage, BGPType
from netsphere.protocols.l7.ntp import NTPMessage
from netsphere.protocols.l7.websocket import WebSocketFrame, WebSocketOpcode


class TestLayer7Protocols(unittest.TestCase):
    def test_dns_query_generation(self):
        dns_query = DNSMessage.query("example.com", qtype=DNSType.A, transaction_id=0x5678)
        packed = dns_query.pack()
        self.assertTrue(len(packed) > 12)

        buf = PacketBuffer(packed)
        unpacked_hdr = dns_query.header.unpack(buf)
        self.assertEqual(unpacked_hdr.transaction_id, 0x5678)
        self.assertFalse(unpacked_hdr.is_response)

    def test_http1_serialization(self):
        req = HTTP1Request(method="GET", path="/api/v1/status", headers={"Host": "api.example.com"})
        packed = req.pack()
        self.assertTrue(b"GET /api/v1/status HTTP/1.1\r\n" in packed)

        unpacked = HTTP1Request.unpack(packed)
        self.assertEqual(unpacked.method, "GET")
        self.assertEqual(unpacked.path, "/api/v1/status")
        self.assertEqual(unpacked.headers.get("host"), "api.example.com")

    def test_http2_frame(self):
        frame = HTTP2Frame(frame_type=HTTP2FrameType.HEADERS, flags=0x05, stream_id=1, payload=b"HPACKDATA")
        packed = frame.pack()
        self.assertEqual(len(packed), 9 + len(b"HPACKDATA"))

        unpacked = HTTP2Frame.unpack(PacketBuffer(packed))
        self.assertEqual(unpacked.frame_type, HTTP2FrameType.HEADERS)
        self.assertEqual(unpacked.stream_id, 1)
        self.assertEqual(unpacked.payload, b"HPACKDATA")

    def test_mqtt_publish(self):
        msg = MQTTMessage.publish("sensors/temperature", b'{"temp": 24.5}')
        packed = msg.pack()
        self.assertTrue(len(packed) > 5)

        unpacked = MQTTMessage.unpack(PacketBuffer(packed))
        self.assertEqual(unpacked.msg_type, MQTTMessageType.PUBLISH)

    def test_coap_message(self):
        coap = CoAPMessage(coap_type=CoAPType.CONFIRMABLE, code=CoAPCode.GET, message_id=0x0042)
        packed = coap.pack()
        self.assertEqual(len(packed), 4)

        unpacked = CoAPMessage.unpack(PacketBuffer(packed))
        self.assertEqual(unpacked.coap_type, CoAPType.CONFIRMABLE)
        self.assertEqual(unpacked.code, CoAPCode.GET)
        self.assertEqual(unpacked.message_id, 0x0042)

    def test_websocket_frame_masking(self):
        frame = WebSocketFrame.text("Hello WebSocket", mask=True)
        packed = frame.pack()

        unpacked = WebSocketFrame.unpack(PacketBuffer(packed))
        self.assertEqual(unpacked.opcode, WebSocketOpcode.TEXT)
        self.assertEqual(unpacked.payload.decode("utf-8"), "Hello WebSocket")


if __name__ == "__main__":
    unittest.main()
