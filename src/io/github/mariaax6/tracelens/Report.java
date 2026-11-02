package io.github.mariaax6.tracelens;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Renders an analysis as HTML (bounded preview), CSV (every flow) and JSON (summary and alerts). */
public final class Report {
    private Report() {}

    /** Everything a report needs, gathered once. */
    public record Result(String inputName, String version, PcapReader.Summary summary, Analyzer analyzer) {}

    static String utc(long nanos) {
        return DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochSecond(Math.floorDiv(nanos, 1_000_000_000L), Math.floorMod(nanos, 1_000_000_000L)));
    }

    static String epoch(long nanos) {
        return Math.floorDiv(nanos, 1_000_000_000L) + "." + String.format("%09d", Math.floorMod(nanos, 1_000_000_000L));
    }

    static String seconds(long nanos) {
        return BigDecimal.valueOf(nanos, 9).stripTrailingZeros().toPlainString();
    }

    static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    static String quote(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> { if (c < 32) out.append(String.format("\\u%04x", (int) c)); else out.append(c); }
            }
        }
        return out.append('"').toString();
    }

    static String csvField(String s) {
        return s.contains(",") || s.contains("\"") || s.contains("\n") ? "\"" + s.replace("\"", "\"\"") + "\"" : s;
    }

    static String portSummary(Analyzer.Alert a) {
        String ports = a.samplePorts().stream().map(String::valueOf).collect(Collectors.joining(", "));
        return a.distinctPorts() > a.samplePorts().size() ? ports + ", …" : ports;
    }

    public static String csv(Analyzer analyzer) {
        StringBuilder out = new StringBuilder("source,destination,protocol,protocol_name,source_port,destination_port,packets,wire_bytes,tcp_flags,first_epoch,last_epoch,first_utc,last_utc\n");
        for (var e : analyzer.flows().entrySet()) {
            var k = e.getKey(); var f = e.getValue();
            out.append(k.source()).append(',').append(k.destination()).append(',').append(k.protocol()).append(',')
               .append(Packet.protocolName(k.protocol())).append(',').append(k.sourcePort()).append(',').append(k.destinationPort()).append(',')
               .append(f.packets()).append(',').append(f.wireBytes()).append(',').append(csvField(Packet.flagNames(f.tcpFlags()))).append(',')
               .append(epoch(f.firstNanos())).append(',').append(epoch(f.lastNanos())).append(',')
               .append(utc(f.firstNanos())).append(',').append(utc(f.lastNanos())).append('\n');
        }
        return out.toString();
    }

    public static String json(Result r) {
        var s = r.summary(); var a = r.analyzer();
        StringBuilder out = new StringBuilder();
        out.append("{\"schemaVersion\":2,\"tool\":\"tracelens\",\"version\":").append(quote(r.version()))
           .append(",\n\"input\":{\"file\":").append(quote(r.inputName())).append(",\"sha256\":").append(quote(s.sha256()))
           .append(",\"linkType\":").append(s.linkType()).append(",\"linkTypeName\":").append(quote(PcapReader.linkTypeName(s.linkType())))
           .append(",\"timestampPrecision\":").append(quote(s.nanosecond() ? "nanosecond" : "microsecond")).append('}')
           .append(",\n\"parameters\":{\"threshold\":").append(a.threshold()).append(",\"windowSeconds\":").append(seconds(a.windowNanos())).append('}')
           .append(",\n\"capture\":{\"records\":").append(s.records())
           .append(",\"first\":").append(s.records() == 0 ? "null" : quote(utc(s.firstNanos())))
           .append(",\"last\":").append(s.records() == 0 ? "null" : quote(utc(s.lastNanos()))).append('}')
           .append(",\n\"coverage\":{\"decoded\":").append(s.decoded()).append(",\"nonIpv4\":").append(s.nonIpv4())
           .append(",\"otherProtocol\":").append(s.otherProtocol()).append(",\"malformed\":").append(s.malformed())
           .append(",\"fragments\":").append(s.fragments()).append(",\"truncated\":").append(s.truncated())
           .append(",\"reordered\":").append(s.reordered()).append('}')
           .append(",\n\"flows\":").append(a.flows().size()).append(",\"untrackedPackets\":").append(a.untrackedPackets())
           .append(",\"unevaluatedSyns\":").append(a.unevaluatedSyns())
           .append(",\n\"alerts\":[");
        boolean first = true;
        for (var alert : a.alerts()) {
            if (!first) out.append(',');
            first = false;
            out.append("\n{\"source\":").append(quote(alert.source())).append(",\"destination\":").append(quote(alert.destination()))
               .append(",\"time\":").append(quote(utc(alert.timeNanos()))).append(",\"windowStart\":").append(quote(utc(alert.windowStartNanos())))
               .append(",\"distinctPorts\":").append(alert.distinctPorts()).append(",\"samplePorts\":")
               .append(alert.samplePorts().stream().map(String::valueOf).collect(Collectors.joining(",", "[", "]"))).append('}');
        }
        return out.append(first ? "]}\n" : "\n]}\n").toString();
    }

    /** Coverage notes worth reading before trusting the numbers; empty when the capture decoded cleanly. */
    public static List<String> warnings(Result r) {
        var s = r.summary(); var a = r.analyzer();
        List<String> out = new ArrayList<>();
        if (s.nonIpv4() > 0) out.add(s.nonIpv4() + " records were not IPv4 (for example IPv6 or ARP) and were not analysed");
        if (s.otherProtocol() > 0) out.add(s.otherProtocol() + " IPv4 packets used a protocol other than TCP, UDP or ICMP");
        if (s.malformed() > 0) out.add(s.malformed() + " records were malformed or incomplete");
        if (s.fragments() > 0) out.add(s.fragments() + " IPv4 fragments were skipped (no reassembly)");
        if (s.truncated() > 0) out.add(s.truncated() + " records were cut by the snapshot length; headers were decoded when complete");
        if (s.reordered() > 0) out.add(s.reordered() + " records had timestamps earlier than a previous record; detection used a monotonic clock");
        if (a.untrackedPackets() > 0) out.add(a.untrackedPackets() + " packets belonged to new flows after the " + Analyzer.MAX_FLOWS + "-flow limit and are missing from the flow table");
        if (a.unevaluatedSyns() > 0) out.add(a.unevaluatedSyns() + " SYNs were not evaluated because " + Analyzer.MAX_PAIRS + " source/destination pairs were already tracked");
        return out;
    }

    private static final String CSS = """
        :root{--bg:#f2f5fa;--fg:#13233a;--card:#fff;--line:#d5dfeb;--muted:#55677e;--accent:#0b7a63;--warn:#8a5a00;--alert:#b0283a;--hero:#0c1424;--hero-fg:#e4ecfa;--hero-num:#69e0c2}
        @media (prefers-color-scheme:dark){:root{--bg:#0c1424;--fg:#e4ecfa;--card:#152238;--line:#2d4563;--muted:#a6b8d0;--accent:#69e0c2;--warn:#e6b455;--alert:#ff7a85;--hero:#081020}}
        body{font:16px/1.6 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0}
        main{max-width:1150px;margin:45px auto;padding:0 22px}
        h1{font-size:46px;margin:0}
        .eyebrow{color:var(--muted);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0}
        section{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:24px;margin:22px 0}
        .metrics{display:flex;gap:35px;flex-wrap:wrap;background:var(--hero);color:var(--hero-fg);border:0}
        .metrics b{font-size:32px;display:block;color:var(--hero-num)}
        table{width:100%;border-collapse:collapse;font-size:14px}
        th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
        td.num,th.num{text-align:right}
        li{margin:12px 0}
        .alert{color:var(--alert)}.warn{color:var(--warn)}.muted,footer{color:var(--muted)}
        code{color:var(--accent)}
        .scroll{overflow:auto}
        """;

    public static String html(Result r, int maxRows) {
        var s = r.summary(); var a = r.analyzer();
        StringBuilder out = new StringBuilder();
        out.append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
           .append("<title>TraceLens · Network evidence</title><style>\n").append(CSS).append("</style></head>\n<body><main>\n")
           .append("<p class=\"eyebrow\">Networks / Systems / Security</p><h1>TraceLens</h1><p>Offline packet evidence, understandable findings.</p>\n")
           .append("<section class=\"metrics\"><div><b>").append(s.records()).append("</b>Records</div><div><b>").append(s.decoded())
           .append("</b>Decoded</div><div><b>").append(a.flows().size()).append("</b>Directional flows</div><div><b>").append(a.alerts().size())
           .append("</b>SYN-pattern alerts</div></section>\n");

        out.append("<section><h2>Capture</h2><p>Input: <code>").append(escapeHtml(r.inputName())).append("</code> · ")
           .append(escapeHtml(PcapReader.linkTypeName(s.linkType()))).append(" · ").append(s.nanosecond() ? "nanosecond" : "microsecond")
           .append(" timestamps</p>");
        if (s.records() > 0) out.append("<p>From ").append(utc(s.firstNanos())).append(" to ").append(utc(s.lastNanos())).append(" (UTC)</p>");
        out.append("<p class=\"muted\">SHA-256: <code>").append(s.sha256()).append("</code></p>");
        out.append("<p>Not IPv4: ").append(s.nonIpv4()).append(" · Other IPv4 protocols: ").append(s.otherProtocol())
           .append(" · Malformed/incomplete: ").append(s.malformed()).append(" · Fragments skipped: ").append(s.fragments())
           .append(" · Snaplen-truncated: ").append(s.truncated()).append(" · Reordered timestamps: ").append(s.reordered()).append("</p>");
        List<String> warnings = warnings(r);
        if (!warnings.isEmpty()) {
            out.append("<ul class=\"warn\">");
            for (String w : warnings) out.append("<li>").append(escapeHtml(w)).append("</li>");
            out.append("</ul>");
        }
        out.append("<p class=\"muted\">Zero alerts does not mean a safe network.</p></section>\n");

        out.append("<section><h2>Investigation queue</h2><p>Rule: at least ").append(a.threshold()).append(" distinct TCP destination ports receiving SYN without ACK within ")
           .append(seconds(a.windowNanos())).append(" s, per source/destination pair. Retransmissions to one port do not add diversity; ")
           .append("each pair can alert again only after one window has passed.</p><ul>");
        if (a.alerts().isEmpty()) out.append("<li>No threshold crossings.</li>");
        for (var alert : a.alerts()) {
            out.append("<li><strong class=\"alert\">").append(escapeHtml(alert.source())).append(" → ").append(escapeHtml(alert.destination()))
               .append("</strong> at ").append(utc(alert.timeNanos())).append(": ").append(alert.distinctPorts()).append(" distinct ports since ")
               .append(utc(alert.windowStartNanos())).append(" (").append(escapeHtml(portSummary(alert)))
               .append("). Investigate; this is a lead, not proof of an attack.</li>");
        }
        out.append("</ul></section>\n");

        List<Map.Entry<Analyzer.Key, Analyzer.Flow>> sorted = new ArrayList<>(a.flows().entrySet());
        sorted.sort(Comparator.comparingLong((Map.Entry<Analyzer.Key, Analyzer.Flow> e) -> e.getValue().packets()).reversed()
                .thenComparingLong(e -> e.getValue().firstNanos()));
        int shown = Math.min(maxRows, sorted.size());
        out.append("<section><h2>Directional flows</h2><p>Showing ").append(shown).append(" of ").append(sorted.size())
           .append(" flows, most packets first. <code>flows.csv</code> contains every flow in order of first appearance.</p>")
           .append("<div class=\"scroll\"><table><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>TCP flags</th>")
           .append("<th class=\"num\">Packets</th><th class=\"num\">Wire bytes</th><th>First seen (UTC)</th></tr>");
        for (int i = 0; i < shown; i++) {
            var k = sorted.get(i).getKey(); var f = sorted.get(i).getValue();
            out.append("<tr><td>").append(escapeHtml(k.source())).append(':').append(k.sourcePort()).append("</td><td>")
               .append(escapeHtml(k.destination())).append(':').append(k.destinationPort()).append("</td><td>")
               .append(Packet.protocolName(k.protocol())).append("</td><td>").append(Packet.flagNames(f.tcpFlags()))
               .append("</td><td class=\"num\">").append(f.packets()).append("</td><td class=\"num\">").append(f.wireBytes())
               .append("</td><td>").append(utc(f.firstNanos())).append("</td></tr>");
        }
        return out.append("</table></div></section>\n<footer>TraceLens ").append(escapeHtml(r.version()))
                  .append(" · Classic PCAP · Ethernet, Linux SLL or raw IPv4 · No payload inspection, decryption or live capture. ")
                  .append("Wire bytes are original frame lengths, not payload bytes.</footer>\n</main></body></html>\n").toString();
    }
}
