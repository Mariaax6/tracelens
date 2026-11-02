package io.github.mariaax6.tracelens;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Deterministic synthetic frames and PCAP files; never opens a socket.
 * Addresses come from documentation ranges (RFC 5737). Run {@code main} to regenerate {@code examples/}.
 */
public final class Fixtures {
    private Fixtures() {}

    static final long SECOND = 1_000_000_000L;
    static final long BASE = 1_700_000_000L * SECOND;

    /** A frame to write; {@code original} may exceed the data length to model snaplen truncation upstream. */
    public record Frame(long nanos, byte[] data, long original) {
        public Frame(long nanos, byte[] data) { this(nanos, data, data.length); }
    }

    /** Ethernet + IPv4 frame from 192.0.2.{sourceHost} port 44000 to 198.51.100.10, with valid checksums. */
    public static byte[] ipv4(int proto, int sourceHost, int destinationPort, int flags, int payload) {
        int header = proto == Packet.TCP ? 20 : 8, transportLength = header + payload;
        byte[] b = new byte[14 + 20 + transportLength];
        Arrays.fill(b, 0, 6, (byte) 0x22);
        Arrays.fill(b, 6, 12, (byte) 0x44);
        b[12] = 8;
        b[14] = 0x45;
        put16(b, 16, 20 + transportLength);
        b[22] = 64;
        b[23] = (byte) proto;
        b[26] = (byte) 192; b[27] = 0; b[28] = 2; b[29] = (byte) sourceHost;
        b[30] = (byte) 198; b[31] = 51; b[32] = 100; b[33] = 10;
        if (proto == Packet.TCP || proto == Packet.UDP) { put16(b, 34, 44000); put16(b, 36, destinationPort); }
        if (proto == Packet.TCP) { b[46] = 0x50; b[47] = (byte) flags; put16(b, 48, 65535); }
        else if (proto == Packet.UDP) put16(b, 38, transportLength);
        else if (proto == Packet.ICMP) b[34] = 8;
        fixIpChecksum(b, 14);
        if (proto == Packet.TCP) {
            int sum = proto + transportLength; // pseudo-header: protocol and TCP length
            for (int i = 26; i < 34; i += 2) sum += ((b[i] & 255) << 8) | (b[i + 1] & 255);
            put16(b, 50, checksum(b, 34, transportLength, sum));
        } else if (proto == Packet.ICMP) {
            put16(b, 36, checksum(b, 34, transportLength, 0));
        } // UDP checksum 0 means "not used" in IPv4
        return b;
    }

    public static byte[] packet(int proto, int sourceHost, int destinationPort, int flags) {
        return ipv4(proto, sourceHost, destinationPort, flags, 0);
    }

    public static void fixIpChecksum(byte[] b, int ipOffset) {
        b[ipOffset + 10] = 0; b[ipOffset + 11] = 0;
        put16(b, ipOffset + 10, checksum(b, ipOffset, (b[ipOffset] & 15) * 4, 0));
    }

    /** Ethernet frame with another EtherType (e.g. 0x0806 ARP, 0x86dd IPv6) and a zero body. */
    public static byte[] ethernet(int etherType, int bodyLength) {
        byte[] b = new byte[14 + bodyLength];
        Arrays.fill(b, 0, 6, (byte) 0x22);
        Arrays.fill(b, 6, 12, (byte) 0x44);
        put16(b, 12, etherType);
        if (etherType == 0x86dd && bodyLength > 0) b[14] = 0x60;
        return b;
    }

    /** Re-frames an Ethernet frame as Linux cooked capture (SLL, 16-byte header). */
    public static byte[] toSll(byte[] ethernet) {
        byte[] b = new byte[16 + ethernet.length - 14];
        put16(b, 2, 1);      // ARPHRD_ETHER
        put16(b, 4, 6);      // address length
        System.arraycopy(ethernet, 6, b, 6, 6);
        b[14] = ethernet[12]; b[15] = ethernet[13];
        System.arraycopy(ethernet, 14, b, 16, ethernet.length - 14);
        return b;
    }

    /** Strips the Ethernet header, leaving a raw IP packet. */
    public static byte[] toRaw(byte[] ethernet) {
        return Arrays.copyOfRange(ethernet, 14, ethernet.length);
    }

    /** Inserts 802.1Q tags (VLAN 1) after the MAC addresses. */
    public static byte[] withVlanTags(byte[] ethernet, int tags) {
        byte[] b = new byte[ethernet.length + 4 * tags];
        System.arraycopy(ethernet, 0, b, 0, 12);
        for (int t = 0; t < tags; t++) { put16(b, 12 + 4 * t, 0x8100); put16(b, 14 + 4 * t, 1); }
        System.arraycopy(ethernet, 12, b, 12 + 4 * tags, ethernet.length - 12);
        return b;
    }

    static void put16(byte[] b, int i, int v) { b[i] = (byte) (v >>> 8); b[i + 1] = (byte) v; }

    static int checksum(byte[] b, int start, int length, int sum) {
        for (int i = start; i < start + length; i += 2) sum += ((b[i] & 255) << 8) | (i + 1 < start + length ? b[i + 1] & 255 : 0);
        while ((sum >>> 16) != 0) sum = (sum & 65535) + (sum >>> 16);
        return (~sum) & 65535;
    }

    public static void write(Path path, List<Frame> frames, ByteOrder order, boolean nano) throws IOException {
        write(path, frames, order, nano, PcapReader.LINKTYPE_ETHERNET, 65535);
    }

    public static void write(Path path, List<Frame> frames, ByteOrder order, boolean nano, int linkType, int snaplen) throws IOException {
        try (OutputStream out = Files.newOutputStream(path)) {
            ByteBuffer h = ByteBuffer.allocate(24).order(order);
            h.putInt(nano ? 0xa1b23c4d : 0xa1b2c3d4).putShort((short) 2).putShort((short) 4).putInt(0).putInt(0).putInt(snaplen).putInt(linkType);
            out.write(h.array());
            for (Frame f : frames) {
                long sec = f.nanos() / SECOND, rest = f.nanos() % SECOND;
                int captured = Math.min(f.data().length, snaplen);
                ByteBuffer r = ByteBuffer.allocate(16).order(order);
                r.putInt((int) sec).putInt((int) (nano ? rest : rest / 1000)).putInt(captured).putInt((int) f.original());
                out.write(r.array());
                out.write(f.data(), 0, captured);
            }
        }
    }

    /** Writes demo.pcap, slow-diverse.pcap and coverage.pcap into {@code dir}. */
    public static void generate(Path dir) throws IOException {
        Files.createDirectories(dir);
        List<Frame> demo = new ArrayList<>();
        for (int i = 0; i < 8; i++) demo.add(new Frame(BASE + i * 250_000_000L, packet(Packet.UDP, 5, 53, 0)));
        for (int i = 0; i < 16; i++) demo.add(new Frame(BASE + 3 * SECOND + i * 200_000_000L, packet(Packet.TCP, 20, 1000 + i, Packet.SYN)));
        for (int i = 0; i < 8; i++) demo.add(new Frame(BASE + 8 * SECOND + i * 100_000_000L, packet(Packet.TCP, 7, 443, Packet.SYN)));
        demo.add(new Frame(BASE + 10 * SECOND, packet(Packet.ICMP, 5, 0, 0)));
        write(dir.resolve("demo.pcap"), demo, ByteOrder.LITTLE_ENDIAN, false);

        List<Frame> slow = new ArrayList<>();
        for (int i = 0; i < 20; i++) slow.add(new Frame(BASE + i * 11 * SECOND, packet(Packet.TCP, 5, 1000 + i, Packet.SYN)));
        write(dir.resolve("slow-diverse.pcap"), slow, ByteOrder.BIG_ENDIAN, true);

        long ms = 1_000_000L;
        byte[] bulk = ipv4(Packet.TCP, 30, 443, Packet.ACK | Packet.PSH, 1400);
        byte[] dns = ipv4(Packet.UDP, 30, 53, 0, 300);
        byte[] fragment = packet(Packet.UDP, 30, 53, 0);
        fragment[20] = 0x20; // more-fragments flag
        fixIpChecksum(fragment, 14);
        byte[] gre = ipv4(47, 30, 0, 0, 0);
        byte[] badIhl = packet(Packet.TCP, 30, 443, Packet.SYN);
        badIhl[14] = 0x44; // header length 16 bytes: invalid
        List<Frame> coverage = List.of(
            new Frame(BASE, toSll(packet(Packet.TCP, 30, 443, Packet.SYN))),
            new Frame(BASE + 100 * ms, toSll(bulk)),
            new Frame(BASE + 200 * ms, toSll(dns)),
            new Frame(BASE + 150 * ms, toSll(packet(Packet.ICMP, 30, 0, 0))),
            new Frame(BASE + 300 * ms, toSll(ethernet(0x86dd, 40))),
            new Frame(BASE + 400 * ms, toSll(ethernet(0x0806, 28))),
            new Frame(BASE + 500 * ms, toSll(fragment)),
            new Frame(BASE + 600 * ms, toSll(gre)),
            new Frame(BASE + 700 * ms, toSll(badIhl)));
        write(dir.resolve("coverage.pcap"), coverage, ByteOrder.LITTLE_ENDIAN, false, PcapReader.LINKTYPE_LINUX_SLL, 96);
    }

    public static void main(String[] args) throws IOException {
        Path dir = Path.of(args.length == 0 ? "examples" : args[0]);
        generate(dir);
        System.out.println("Synthetic fixtures written to " + dir + ": demo.pcap, slow-diverse.pcap, coverage.pcap");
    }
}
