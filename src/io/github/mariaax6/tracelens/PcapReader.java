package io.github.mariaax6.tracelens;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.function.Consumer;

/** Streaming classic-PCAP reader. No live capture, native library or network access. */
public final class PcapReader {
    private PcapReader() {}

    public static final int LINKTYPE_ETHERNET = 1, LINKTYPE_RAW = 101, LINKTYPE_LINUX_SLL = 113, LINKTYPE_IPV4 = 228;
    static final long MAX_SNAPLEN = 16L * 1024 * 1024;
    static final long MAX_RECORDS = 50_000_000L;

    /**
     * Coverage counters. {@code decoded + nonIpv4 + otherProtocol + malformed + fragments == records}.
     * {@code truncated} and {@code reordered} are informational and overlap with the others.
     */
    public record Summary(String sha256, int linkType, boolean nanosecond, long records, long decoded,
                          long nonIpv4, long otherProtocol, long malformed, long fragments,
                          long truncated, long reordered, long firstNanos, long lastNanos) {}

    public static String linkTypeName(int linkType) {
        return switch (linkType) {
            case LINKTYPE_ETHERNET -> "Ethernet";
            case LINKTYPE_LINUX_SLL -> "Linux cooked capture (SLL)";
            case LINKTYPE_RAW, LINKTYPE_IPV4 -> "Raw IP";
            default -> "link type " + linkType;
        };
    }

    private static int u16(byte[] b, int n) { return ((b[n] & 255) << 8) | (b[n + 1] & 255); }

    private static String ip(byte[] b, int n) {
        return (b[n] & 255) + "." + (b[n + 1] & 255) + "." + (b[n + 2] & 255) + "." + (b[n + 3] & 255);
    }

    private enum Outcome { DECODED, NON_IPV4, OTHER_PROTOCOL, MALFORMED, FRAGMENT }

    public static Summary read(Path path, Consumer<Packet> sink) throws IOException {
        MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); } catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
        long records = 0, decoded = 0, nonIpv4 = 0, other = 0, malformed = 0, fragments = 0, truncated = 0, reordered = 0;
        long first = Long.MAX_VALUE, last = Long.MIN_VALUE, latest = Long.MIN_VALUE;
        int linkType;
        boolean nano;
        try (InputStream in = new DigestInputStream(new BufferedInputStream(Files.newInputStream(path)), digest)) {
            byte[] header = in.readNBytes(24);
            if (header.length != 24) throw new IOException("Truncated PCAP global header");
            int magic = ByteBuffer.wrap(header).getInt();
            nano = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
            ByteOrder order = switch (magic) {
                case 0xa1b2c3d4, 0xa1b23c4d -> ByteOrder.BIG_ENDIAN;
                case 0xd4c3b2a1, 0x4d3cb2a1 -> ByteOrder.LITTLE_ENDIAN;
                case 0x0a0d0d0a -> throw new IOException("PCAPNG is not supported; convert with: editcap -F pcap in.pcapng out.pcap");
                default -> throw new IOException("Not a classic PCAP file");
            };
            ByteBuffer h = ByteBuffer.wrap(header).order(order);
            if (h.getShort(4) != 2 || h.getShort(6) != 4) throw new IOException("Unsupported PCAP version");
            long snap = Integer.toUnsignedLong(h.getInt(16));
            if (snap == 0 || snap > MAX_SNAPLEN) throw new IOException("Invalid or excessive snapshot length");
            linkType = h.getInt(20) & 0x0FFFFFFF; // upper bits may carry FCS information
            if (linkType != LINKTYPE_ETHERNET && linkType != LINKTYPE_LINUX_SLL && linkType != LINKTYPE_RAW && linkType != LINKTYPE_IPV4) {
                throw new IOException("Unsupported link type " + linkType + " (supported: Ethernet, Linux SLL, raw IPv4)");
            }
            long fractionLimit = nano ? 1_000_000_000L : 1_000_000L;
            while (true) {
                byte[] rh = in.readNBytes(16);
                if (rh.length == 0) break;
                if (rh.length != 16) throw new IOException("Truncated packet record header after record " + records);
                if (++records > MAX_RECORDS) throw new IOException("Safety limit: " + MAX_RECORDS + " records");
                ByteBuffer r = ByteBuffer.wrap(rh).order(order);
                long seconds = Integer.toUnsignedLong(r.getInt()), fraction = Integer.toUnsignedLong(r.getInt());
                long captured = Integer.toUnsignedLong(r.getInt()), original = Integer.toUnsignedLong(r.getInt());
                if (captured > snap || captured > original) throw new IOException("Invalid captured length at record " + records);
                if (fraction >= fractionLimit) throw new IOException("Invalid timestamp fraction at record " + records);
                long time = seconds * 1_000_000_000L + (nano ? fraction : fraction * 1_000L);
                first = Math.min(first, time);
                if (time < latest) reordered++; else latest = time;
                last = Math.max(last, time);
                byte[] b = in.readNBytes((int) captured);
                if (b.length != captured) throw new IOException("Truncated packet data at record " + records);
                boolean cut = captured < original;
                if (cut) truncated++;
                Packet[] result = new Packet[1];
                switch (decode(b, linkType, cut, time, original, result)) {
                    case DECODED -> { sink.accept(result[0]); decoded++; }
                    case NON_IPV4 -> nonIpv4++;
                    case OTHER_PROTOCOL -> other++;
                    case MALFORMED -> malformed++;
                    case FRAGMENT -> fragments++;
                }
            }
        }
        if (records == 0) { first = 0; last = 0; }
        return new Summary(HexFormat.of().formatHex(digest.digest()), linkType, nano, records, decoded,
                nonIpv4, other, malformed, fragments, truncated, reordered, first, last);
    }

    /**
     * Decodes link, IPv4 and transport headers. When the record was cut by the snapshot length,
     * headers are still decoded if they are complete; only the declared lengths are checked.
     */
    private static Outcome decode(byte[] b, int linkType, boolean cut, long time, long original, Packet[] out) {
        int offset;
        if (linkType == LINKTYPE_RAW || linkType == LINKTYPE_IPV4) {
            if (b.length < 1) return Outcome.MALFORMED;
            if ((b[0] >>> 4 & 15) != 4) return Outcome.NON_IPV4;
            offset = 0;
        } else {
            int ether;
            if (linkType == LINKTYPE_ETHERNET) {
                if (b.length < 14) return Outcome.MALFORMED;
                ether = u16(b, 12); offset = 14;
            } else {
                if (b.length < 16) return Outcome.MALFORMED;
                ether = u16(b, 14); offset = 16;
            }
            int tags = 0;
            while (ether == 0x8100 || ether == 0x88a8) {
                if (++tags > 2) return Outcome.NON_IPV4;
                if (b.length < offset + 4) return Outcome.MALFORMED;
                ether = u16(b, offset + 2); offset += 4;
            }
            if (ether != 0x0800) return Outcome.NON_IPV4;
        }
        if (b.length < offset + 20) return Outcome.MALFORMED;
        int version = b[offset] >>> 4 & 15, ihl = (b[offset] & 15) * 4, total = u16(b, offset + 2);
        if (version != 4 || ihl < 20 || total < ihl || b.length < offset + ihl) return Outcome.MALFORMED;
        int declaredEnd = offset + total;
        if (b.length < declaredEnd && !cut) return Outcome.MALFORMED; // whole frame captured, yet IP claims more
        if ((u16(b, offset + 6) & 0x3fff) != 0) return Outcome.FRAGMENT;
        int proto = b[offset + 9] & 255, transport = offset + ihl;
        int sp = 0, dp = 0, flags = 0;
        if (proto == Packet.TCP) {
            if (declaredEnd < transport + 20 || b.length < transport + 14) return Outcome.MALFORMED;
            int tcpHeader = (b[transport + 12] >>> 4 & 15) * 4;
            if (tcpHeader < 20 || transport + tcpHeader > declaredEnd) return Outcome.MALFORMED;
            sp = u16(b, transport); dp = u16(b, transport + 2); flags = b[transport + 13] & 255;
        } else if (proto == Packet.UDP) {
            if (declaredEnd < transport + 8 || b.length < transport + 6) return Outcome.MALFORMED;
            int udpLength = u16(b, transport + 4);
            if (udpLength < 8 || transport + udpLength > declaredEnd) return Outcome.MALFORMED;
            sp = u16(b, transport); dp = u16(b, transport + 2);
        } else if (proto == Packet.ICMP) {
            if (declaredEnd < transport + 8) return Outcome.MALFORMED;
        } else {
            return Outcome.OTHER_PROTOCOL;
        }
        out[0] = new Packet(time, ip(b, offset + 12), ip(b, offset + 16), proto, sp, dp, flags, original);
        return Outcome.DECODED;
    }
}
