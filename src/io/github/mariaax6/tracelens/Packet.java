package io.github.mariaax6.tracelens;

/**
 * One decoded IPv4 packet header.
 *
 * @param timeNanos       capture timestamp, nanoseconds since the Unix epoch
 * @param protocol        IPv4 protocol number (1 ICMP, 6 TCP, 17 UDP)
 * @param sourcePort      0 for ICMP
 * @param destinationPort 0 for ICMP
 * @param tcpFlags        TCP flag byte, 0 for other protocols
 * @param wireBytes       original frame length on the wire (not payload bytes)
 */
public record Packet(long timeNanos, String source, String destination, int protocol,
                     int sourcePort, int destinationPort, int tcpFlags, long wireBytes) {

    public static final int ICMP = 1, TCP = 6, UDP = 17;
    public static final int FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10, URG = 0x20;

    public static String protocolName(int protocol) {
        return switch (protocol) {
            case ICMP -> "ICMP";
            case TCP -> "TCP";
            case UDP -> "UDP";
            default -> Integer.toString(protocol);
        };
    }

    /** Human-readable TCP flags such as "SYN,ACK"; empty when none are set. */
    public static String flagNames(int flags) {
        String[] names = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < names.length; i++) {
            if ((flags & (1 << i)) != 0) {
                if (out.length() > 0) out.append(',');
                out.append(names[i]);
            }
        }
        return out.toString();
    }
}
