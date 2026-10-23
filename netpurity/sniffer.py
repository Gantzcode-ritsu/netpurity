"""Scapy-based sniffer that reports DNS queries to a callback."""

import errno
import logging
from typing import Callable, Optional

from scapy.all import (
    DNS,
    DNSQR,
    IP,
    UDP,
    IPv6,
    Packet,
    Scapy_Exception,
    bind_layers,
    conf,
    get_if_list,
    sniff,
)

from netpurity.utils import decode_qname

logger = logging.getLogger(__name__)

#: Signature of the callback that receives each DNS query: (src_ip, domain, timestamp).
QueryCallback = Callable[[str, str, float], None]


class SnifferError(RuntimeError):
    """Raised when capture cannot start: unknown interface or missing privileges."""


def interface_exists(interface: str) -> bool:
    """Return True if scapy knows an interface called ``interface``."""
    if interface in get_if_list():
        return True
    try:
        # dev_from_name resolves friendly names such as "Wi-Fi" on Windows.
        conf.ifaces.dev_from_name(interface)
    except (ValueError, KeyError, AttributeError):
        return False
    return True


class DnsSniffer:
    """Capture DNS queries (qr=0) on one interface and pass each to ``on_query``."""

    def __init__(self, interface: str, on_query: QueryCallback, port: int = 53) -> None:
        """Configure the sniffer. Capture begins when you call :meth:`start`."""
        self.interface = interface
        self.port = port
        self.bpf_filter = f"udp port {port}"
        self._on_query = on_query
        if port != 53:
            # Scapy decodes DNS on well-known ports, so bind the custom port.
            bind_layers(UDP, DNS, dport=port)
            bind_layers(UDP, DNS, sport=port)

    def start(self) -> None:
        """Sniff until the user presses Ctrl+C.

        Raises:
            SnifferError: the interface does not exist, privileges are missing,
                or scapy fails to start the capture.
        """
        if not interface_exists(self.interface):
            available = ", ".join(get_if_list()) or "none found"
            raise SnifferError(
                f"Network interface {self.interface!r} does not exist. "
                f"Available interfaces: {available}"
            )

        logger.info(
            "Sniffing on %s with BPF filter %r (Ctrl+C to stop)",
            self.interface,
            self.bpf_filter,
        )
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,
            )
        except KeyboardInterrupt:
            logger.info("User stopped the sniffer")
        except OSError as exc:
            if isinstance(exc, PermissionError) or exc.errno in (errno.EPERM, errno.EACCES):
                raise SnifferError(
                    f"Insufficient privileges to sniff on {self.interface!r}. "
                    "Run as root (sudo) or as Administrator."
                ) from exc
            if exc.errno in (errno.ENODEV, errno.ENXIO):
                raise SnifferError(
                    f"Network interface {self.interface!r} is not available: {exc}"
                ) from exc
            raise SnifferError(f"Cannot sniff on {self.interface!r}: {exc}") from exc
        except Scapy_Exception as exc:
            raise SnifferError(
                f"Scapy could not start the capture on {self.interface!r}: {exc}. "
                "Run as root or Administrator and install libpcap, Npcap or tcpdump."
            ) from exc

    def _handle_packet(self, packet: Packet) -> None:
        """Extract (src_ip, domain, timestamp) from a DNS query and call the callback."""
        try:
            if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
                return
            if packet[DNS].qr != 0:
                return
            src_ip = self._source_ip(packet)
            domain = decode_qname(packet[DNSQR].qname)
            timestamp = float(packet.time)
        except Exception:  # Skip malformed packets and keep capturing.
            logger.debug("Skipping malformed packet", exc_info=True)
            return

        if src_ip is None or not domain:
            return

        try:
            self._on_query(src_ip, domain, timestamp)
        except Exception:  # Log a failing callback and keep capturing.
            logger.exception("on_query callback failed for %s", domain)

    @staticmethod
    def _source_ip(packet: Packet) -> Optional[str]:
        """Return the source address of the IPv4 or IPv6 layer, or None."""
        if packet.haslayer(IP):
            return str(packet[IP].src)
        if packet.haslayer(IPv6):
            return str(packet[IPv6].src)
        return None
