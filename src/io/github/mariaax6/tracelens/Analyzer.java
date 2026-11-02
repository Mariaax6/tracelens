package io.github.mariaax6.tracelens;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/** Directional flow aggregation and a bounded, time-window SYN port-diversity heuristic. */
public final class Analyzer {
    public static final int MAX_FLOWS = 100_000;
    public static final int MAX_PAIRS = 200_000;
    static final long MAX_WINDOW_NANOS = 86_400L * 1_000_000_000L;

    public record Key(String source, String destination, int protocol, int sourcePort, int destinationPort) {}

    public static final class Flow {
        long packets, wireBytes, firstNanos, lastNanos;
        int tcpFlags;
        Flow(long time) { firstNanos = lastNanos = time; }
        public long packets() { return packets; }
        public long wireBytes() { return wireBytes; }
        public long firstNanos() { return firstNanos; }
        public long lastNanos() { return lastNanos; }
        /** Union of TCP flags seen in this direction. */
        public int tcpFlags() { return tcpFlags; }
    }

    /**
     * A threshold crossing. {@code windowStartNanos} is the oldest attempt still counted;
     * {@code samplePorts} lists up to 20 of the distinct ports, ascending.
     */
    public record Alert(String source, String destination, long timeNanos, long windowStartNanos,
                        int distinctPorts, List<Integer> samplePorts) {}

    /** Per source/destination pair: latest SYN time per destination port, oldest first. */
    private static final class Window {
        final LinkedHashMap<Integer, Long> latestByPort = new LinkedHashMap<>();
        long latest;
        long lastAlert = Long.MIN_VALUE;
    }

    private final Map<Key, Flow> flows = new LinkedHashMap<>();
    private final Map<String, Window> windows = new HashMap<>();
    private final List<Alert> alerts = new ArrayList<>();
    private final int threshold;
    private final long windowNanos;
    private long clock = Long.MIN_VALUE, lastFullSweep = Long.MIN_VALUE;
    private long synCount, untrackedPackets, unevaluatedSyns;

    public Analyzer(int threshold, long windowNanos) {
        if (threshold < 2 || threshold > 65_536) throw new IllegalArgumentException("Threshold must be between 2 and 65536 ports");
        if (windowNanos <= 0 || windowNanos > MAX_WINDOW_NANOS) throw new IllegalArgumentException("Window must be greater than 0 and at most 86400 seconds");
        this.threshold = threshold;
        this.windowNanos = windowNanos;
    }

    public void accept(Packet p) {
        Key k = new Key(p.source(), p.destination(), p.protocol(), p.sourcePort(), p.destinationPort());
        Flow f = flows.get(k);
        if (f == null && flows.size() < MAX_FLOWS) {
            f = new Flow(p.timeNanos());
            flows.put(k, f);
        }
        if (f == null) {
            untrackedPackets++;
        } else {
            f.packets++;
            f.wireBytes += p.wireBytes();
            f.firstNanos = Math.min(f.firstNanos, p.timeNanos());
            f.lastNanos = Math.max(f.lastNanos, p.timeNanos());
            f.tcpFlags |= p.tcpFlags();
        }
        // Slightly out-of-order timestamps are common in real captures; the window uses a monotonic clock.
        clock = Math.max(clock, p.timeNanos());
        if (p.protocol() != Packet.TCP || (p.tcpFlags() & (Packet.SYN | Packet.ACK)) != Packet.SYN) return;
        long now = clock, cutoff = now - windowNanos;
        if ((++synCount & 1023) == 0) windows.values().removeIf(w -> w.latest < cutoff);
        String pair = p.source() + ">" + p.destination();
        Window w = windows.get(pair);
        if (w == null) {
            if (windows.size() >= MAX_PAIRS && now > lastFullSweep) {
                // Table full: sweep stale pairs now (at most once per clock tick) before giving up.
                windows.values().removeIf(x -> x.latest < cutoff);
                lastFullSweep = now;
            }
            if (windows.size() >= MAX_PAIRS) { unevaluatedSyns++; return; }
            w = new Window();
            windows.put(pair, w);
        }
        w.latestByPort.remove(p.destinationPort());
        w.latestByPort.put(p.destinationPort(), now);
        w.latest = now;
        for (Iterator<Long> it = w.latestByPort.values().iterator(); it.hasNext(); ) {
            if (it.next() < cutoff) it.remove(); else break;
        }
        int distinct = w.latestByPort.size();
        if (distinct >= threshold && (w.lastAlert == Long.MIN_VALUE || now - w.lastAlert >= windowNanos)) {
            TreeSet<Integer> ports = new TreeSet<>(w.latestByPort.keySet());
            List<Integer> sample = new ArrayList<>();
            for (int port : ports) { if (sample.size() == 20) break; sample.add(port); }
            long start = w.latestByPort.values().iterator().next();
            alerts.add(new Alert(p.source(), p.destination(), now, start, distinct, List.copyOf(sample)));
            w.lastAlert = now;
        }
    }

    public Map<Key, Flow> flows() { return Collections.unmodifiableMap(flows); }
    public List<Alert> alerts() { return List.copyOf(alerts); }
    public int threshold() { return threshold; }
    public long windowNanos() { return windowNanos; }
    /** Packets of new flows that arrived after {@link #MAX_FLOWS} was reached. */
    public long untrackedPackets() { return untrackedPackets; }
    /** SYNs not evaluated because {@link #MAX_PAIRS} active pairs were already tracked. */
    public long unevaluatedSyns() { return unevaluatedSyns; }
}
