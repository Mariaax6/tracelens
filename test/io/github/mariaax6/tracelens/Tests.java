package io.github.mariaax6.tracelens;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.github.mariaax6.tracelens.Fixtures.Frame;

/** Framework-free checks. Run from the project root (build.sh / build.ps1 do this). */
public final class Tests {
    private static int checks;
    private static final long S = Fixtures.SECOND;
    private static final Path EXAMPLES = Path.of("examples");
    private static Path dir;

    private static void check(boolean condition, String label) {
        checks++;
        if (!condition) throw new AssertionError(label);
    }

    private static void invalid(Path p, String expectedMessage, String label) {
        try {
            PcapReader.read(p, x -> {});
            throw new AssertionError(label + " (accepted)");
        } catch (IOException expected) {
            check(expectedMessage == null || expected.getMessage().contains(expectedMessage), label + ": " + expected.getMessage());
        }
    }

    private static void invalidArg(Runnable r, String label) {
        try { r.run(); throw new AssertionError(label + " (accepted)"); } catch (IllegalArgumentException expected) { checks++; }
    }

    private record Read(PcapReader.Summary summary, List<Packet> packets) {}

    private static Read read(Path p) throws IOException {
        List<Packet> packets = new ArrayList<>();
        return new Read(PcapReader.read(p, packets::add), packets);
    }

    private static Read one(byte[] frame) throws IOException {
        return one(frame, frame.length, PcapReader.LINKTYPE_ETHERNET, 65535);
    }

    private static Read one(byte[] frame, long original, int linkType, int snaplen) throws IOException {
        Path p = dir.resolve("one.pcap");
        Fixtures.write(p, List.of(new Frame(2 * S, frame, original)), ByteOrder.LITTLE_ENDIAN, false, linkType, snaplen);
        return read(p);
    }

    private static Packet syn(long nanos, String src, String dst, int port) {
        return new Packet(nanos, src, dst, Packet.TCP, 40000, port, Packet.SYN, 54);
    }

    private record Result(int code, String out, String err) {}

    private static Result cli(String... args) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(), e = new ByteArrayOutputStream();
        int code = Main.run(args, new PrintStream(o, true, StandardCharsets.UTF_8), new PrintStream(e, true, StandardCharsets.UTF_8));
        return new Result(code, o.toString(StandardCharsets.UTF_8), e.toString(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) throws Exception {
        dir = Files.createTempDirectory("tracelens-tests-");
        try {
            fixtures();
            byteOrderAndPrecision();
            linkTypes();
            rejectedInput();
            decodingEdgeCases();
            coverageExample();
            detection();
            limits();
            reportFormats();
            cliBehaviour();
            System.out.println("TraceLens: " + checks + " checks passed");
        } finally {
            try (var files = Files.walk(dir)) {
                for (Path p : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(p);
            }
        }
    }

    private static void fixtures() throws IOException {
        Path generated = dir.resolve("generated");
        Fixtures.generate(generated);
        for (String name : List.of("demo.pcap", "slow-diverse.pcap", "coverage.pcap")) {
            check(Arrays.equals(Files.readAllBytes(generated.resolve(name)), Files.readAllBytes(EXAMPLES.resolve(name))), "examples/" + name + " matches the fixture generator");
        }
        byte[] tcp = Fixtures.packet(Packet.TCP, 4, 443, Packet.SYN);
        check(Fixtures.checksum(tcp, 14, 20, 0) == 0, "generated IPv4 header checksum verifies");
    }

    private static void byteOrderAndPrecision() throws IOException {
        Path p = dir.resolve("variants.pcap");
        for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            for (boolean nano : List.of(false, true)) {
                Fixtures.write(p, List.of(new Frame(100 * S + 250_000_000L, Fixtures.packet(Packet.TCP, 4, 443, Packet.SYN))), order, nano);
                Read r = read(p);
                check(r.summary().decoded() == 1 && r.summary().nanosecond() == nano, "byte order " + order + ", nanosecond=" + nano);
                check(r.packets().get(0).destinationPort() == 443 && r.packets().get(0).timeNanos() == 100_250_000_000L, "ports and exact timestamp");
            }
        }
        long t = Fixtures.BASE + 1;
        Fixtures.write(p, List.of(new Frame(t, Fixtures.packet(Packet.UDP, 4, 53, 0)), new Frame(t + 1, Fixtures.packet(Packet.UDP, 4, 53, 0))), ByteOrder.BIG_ENDIAN, true);
        Read r = read(p);
        check(r.packets().get(0).timeNanos() == t && r.packets().get(1).timeNanos() == t + 1, "nanosecond timestamps are exact (no floating point)");
        Packet first = r.packets().get(0);
        check(first.source().equals("192.0.2.4") && first.destination().equals("198.51.100.10") && first.sourcePort() == 44000 && first.wireBytes() == 42, "addresses, source port and wire length");
    }

    private static void linkTypes() throws IOException {
        byte[] eth = Fixtures.packet(Packet.TCP, 4, 443, Packet.SYN);
        check(one(Fixtures.toSll(eth), Fixtures.toSll(eth).length, PcapReader.LINKTYPE_LINUX_SLL, 65535).packets().get(0).destinationPort() == 443, "Linux SLL link type");
        check(one(Fixtures.toRaw(eth), Fixtures.toRaw(eth).length, PcapReader.LINKTYPE_RAW, 65535).packets().get(0).destinationPort() == 443, "raw IP link type 101");
        check(one(Fixtures.toRaw(eth), Fixtures.toRaw(eth).length, PcapReader.LINKTYPE_IPV4, 65535).summary().decoded() == 1, "IPv4 link type 228");
        byte[] raw6 = new byte[40]; raw6[0] = 0x60;
        check(one(raw6, 40, PcapReader.LINKTYPE_RAW, 65535).summary().nonIpv4() == 1, "raw IPv6 counted as non-IPv4");
        check(one(Fixtures.withVlanTags(eth, 1)).summary().decoded() == 1, "802.1Q VLAN tag");
        check(one(Fixtures.withVlanTags(eth, 2)).summary().decoded() == 1, "two stacked VLAN tags");
        check(one(Fixtures.withVlanTags(eth, 3)).summary().nonIpv4() == 1, "more than two VLAN tags not decoded");
        check(one(Arrays.copyOf(Fixtures.withVlanTags(eth, 1), 16), 60, PcapReader.LINKTYPE_ETHERNET, 16).summary().malformed() == 1, "VLAN tag cut short is malformed");
        Path p = dir.resolve("link.pcap");
        Fixtures.write(p, List.of(), ByteOrder.LITTLE_ENDIAN, false, 105, 65535);
        invalid(p, "Unsupported link type 105", "unsupported link type rejected by name");
    }

    private static void rejectedInput() throws IOException {
        Path p = dir.resolve("bad.pcap");
        Files.write(p, new byte[12]);
        invalid(p, "global header", "short global header");
        Files.write(p, new byte[] {0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        invalid(p, "PCAPNG", "PCAPNG is recognised and explained");
        Files.write(p, "this is not a capture file at all".getBytes(StandardCharsets.UTF_8));
        invalid(p, "Not a classic PCAP", "arbitrary file rejected");
        Fixtures.write(p, List.of(new Frame(2 * S, Fixtures.packet(Packet.UDP, 4, 53, 0))), ByteOrder.LITTLE_ENDIAN, false);
        byte[] raw = Files.readAllBytes(p);
        Files.write(p, Arrays.copyOf(raw, raw.length - 1));
        invalid(p, "Truncated packet data", "truncated record data");
        Files.write(p, Arrays.copyOf(raw, raw.length + 5));
        invalid(p, "record header", "truncated record header");
        byte[] copy = raw.clone();
        ByteBuffer.wrap(copy).order(ByteOrder.LITTLE_ENDIAN).putInt(32, 1_000_000);
        Files.write(p, copy);
        invalid(p, "captured length", "captured length above snaplen");
        copy = raw.clone();
        ByteBuffer.wrap(copy).order(ByteOrder.LITTLE_ENDIAN).putInt(28, 1_000_000);
        Files.write(p, copy);
        invalid(p, "timestamp fraction", "invalid microsecond fraction");
        copy = raw.clone();
        ByteBuffer.wrap(copy).order(ByteOrder.LITTLE_ENDIAN).putInt(16, 0);
        Files.write(p, copy);
        invalid(p, "snapshot length", "zero snaplen");
        copy = raw.clone();
        ByteBuffer.wrap(copy).order(ByteOrder.LITTLE_ENDIAN).putShort(4, (short) 3);
        Files.write(p, copy);
        invalid(p, "version", "unsupported PCAP version");
    }

    private static void decodingEdgeCases() throws IOException {
        byte[] bulk = Fixtures.ipv4(Packet.TCP, 4, 443, Packet.ACK, 1400);
        Read r = one(bulk, bulk.length, PcapReader.LINKTYPE_ETHERNET, 96);
        check(r.summary().decoded() == 1 && r.summary().truncated() == 1 && r.packets().get(0).wireBytes() == bulk.length, "snaplen-truncated packet still decoded with original wire length");
        check(one(Arrays.copyOf(bulk, 44), bulk.length, PcapReader.LINKTYPE_ETHERNET, 44).summary().malformed() == 1, "record cut inside the TCP header is malformed");
        byte[] lying = Fixtures.packet(Packet.TCP, 4, 443, Packet.SYN);
        Fixtures.put16(lying, 16, 200);
        check(one(lying).summary().malformed() == 1, "IP length beyond a fully captured frame is malformed");
        byte[] padded = Arrays.copyOf(Fixtures.packet(Packet.UDP, 4, 53, 0), 60);
        check(one(padded).summary().decoded() == 1, "Ethernet minimum-size padding tolerated");

        byte[] fragment = Fixtures.packet(Packet.TCP, 4, 22, Packet.SYN);
        fragment[20] = 0x20;
        Path p = dir.resolve("frag.pcap");
        Fixtures.write(p, List.of(new Frame(2 * S, fragment)), ByteOrder.BIG_ENDIAN, false);
        check(PcapReader.read(p, x -> { throw new AssertionError("fragment reached the analyzer"); }).fragments() == 1, "fragments skipped, never analysed");
        check(one(Fixtures.ethernet(0x0806, 28)).summary().nonIpv4() == 1, "ARP counted as non-IPv4");
        check(one(Fixtures.ipv4(47, 4, 0, 0, 0)).summary().otherProtocol() == 1, "GRE counted as other protocol");
        byte[] badOffset = Fixtures.packet(Packet.TCP, 4, 22, Packet.SYN);
        badOffset[46] = 0x10;
        check(one(badOffset).summary().malformed() == 1, "TCP data offset below 20 bytes");
        byte[] badUdp = Fixtures.packet(Packet.UDP, 4, 53, 0);
        Fixtures.put16(badUdp, 38, 4);
        check(one(badUdp).summary().malformed() == 1, "UDP length below 8 bytes");
        byte[] badIhl = Fixtures.packet(Packet.TCP, 4, 22, Packet.SYN);
        badIhl[14] = 0x44;
        check(one(badIhl).summary().malformed() == 1, "IPv4 header length below 20 bytes");
        check(one(new byte[10]).summary().malformed() == 1, "frame shorter than Ethernet header");

        Fixtures.write(p, List.of(new Frame(2 * S, Fixtures.packet(Packet.TCP, 4, 22, Packet.SYN))), ByteOrder.LITTLE_ENDIAN, false);
        byte[] raw = Files.readAllBytes(p);
        ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putInt(36, -1);
        Files.write(p, raw);
        check(read(p).packets().get(0).wireBytes() == 4_294_967_295L, "wire length is unsigned, not a negative int");

        Fixtures.write(p, List.of(new Frame(2 * S, Fixtures.packet(Packet.TCP, 4, 22, Packet.SYN)), new Frame(1 * S, Fixtures.packet(Packet.TCP, 4, 23, Packet.SYN))), ByteOrder.LITTLE_ENDIAN, false);
        r = read(p);
        check(r.summary().decoded() == 2 && r.summary().reordered() == 1, "out-of-order timestamps counted, not fatal");
        check(r.summary().firstNanos() == S && r.summary().lastNanos() == 2 * S, "capture span uses earliest and latest timestamps");

        Fixtures.write(p, List.of(), ByteOrder.LITTLE_ENDIAN, false);
        r = read(p);
        check(r.summary().records() == 0 && r.summary().decoded() == 0, "empty capture is valid");
        check(r.summary().sha256().equals(HexFormat.of().formatHex(sha256(Files.readAllBytes(p)))), "SHA-256 covers the whole input file");
    }

    private static byte[] sha256(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); } catch (Exception e) { throw new AssertionError(e); }
    }

    private static void coverageExample() throws IOException {
        var s = read(EXAMPLES.resolve("coverage.pcap")).summary();
        check(s.records() == 9 && s.decoded() == 4 && s.nonIpv4() == 2 && s.otherProtocol() == 1 && s.malformed() == 1
                && s.fragments() == 1 && s.truncated() == 2 && s.reordered() == 1, "coverage example counters");
        for (String name : List.of("demo.pcap", "slow-diverse.pcap", "coverage.pcap")) {
            var x = read(EXAMPLES.resolve(name)).summary();
            check(x.decoded() + x.nonIpv4() + x.otherProtocol() + x.malformed() + x.fragments() == x.records(), "every record is classified exactly once: " + name);
        }
    }

    private static void detection() throws IOException {
        Analyzer a = new Analyzer(12, 10 * S);
        for (int i = 0; i < 40; i++) a.accept(syn(i * 10_000_000L, "a", "b", 22));
        check(a.alerts().isEmpty(), "retransmissions to one port do not add diversity");
        for (int i = 0; i < 11; i++) a.accept(syn(S + i * 10_000_000L, "a", "b", 100 + i));
        check(a.alerts().size() == 1, "alert at the twelfth distinct port");
        var alert = a.alerts().get(0);
        check(alert.distinctPorts() == 12 && alert.samplePorts().get(0) == 22 && alert.samplePorts().size() == 12 && alert.windowStartNanos() < alert.timeNanos(), "alert details: count, sorted ports, window start");
        check(a.flows().values().stream().mapToLong(Analyzer.Flow::packets).sum() == 51, "flow aggregation conserves packets");

        a = new Analyzer(3, 10 * S);
        for (int i = 0; i < 6; i++) a.accept(syn(i * 11 * S, "a", "b", 100 + i));
        check(a.alerts().isEmpty(), "attempts outside the window expire");
        a = new Analyzer(2, 10 * S);
        a.accept(syn(0, "a", "b", 1));
        a.accept(syn(10 * S, "a", "b", 2));
        check(a.alerts().size() == 1, "window boundary is inclusive");
        a = new Analyzer(3, 10 * S);
        for (int i = 0; i < 10; i++) a.accept(new Packet(i * S, "a", "b", Packet.TCP, 4000, 100 + i, Packet.SYN | Packet.ACK, 54));
        check(a.alerts().isEmpty(), "SYN-ACK excluded");
        a = new Analyzer(3, 10 * S);
        for (int i = 0; i < 30; i++) a.accept(syn(i * 100_000_000L, "a", "b", 100 + i));
        check(a.alerts().size() == 1, "cooldown: one alert per sustained burst within a window");
        for (int i = 0; i < 3; i++) a.accept(syn(20 * S + i, "a", "b", 500 + i));
        check(a.alerts().size() == 2, "a new burst after the cooldown alerts again");
        a = new Analyzer(12, 10 * S);
        for (int i = 0; i < 6; i++) { a.accept(syn(i, "a", "b", 100 + i)); a.accept(syn(i, "a", "c", 200 + i)); }
        check(a.alerts().isEmpty(), "diversity is counted per source/destination pair");
        a = new Analyzer(3, 10 * S);
        a.accept(syn(5 * S, "a", "b", 1));
        a.accept(syn(1 * S, "a", "b", 2));
        a.accept(syn(5 * S, "a", "b", 3));
        check(a.alerts().size() == 1 && a.alerts().get(0).timeNanos() == 5 * S, "reordered SYN counted at the monotonic clock");
        a = new Analyzer(12, 10 * S);
        a.accept(syn(0, "a", "b", 80));
        a.accept(new Packet(1, "a", "b", Packet.TCP, 40000, 80, Packet.ACK, 60));
        check(Packet.flagNames(a.flows().values().iterator().next().tcpFlags()).equals("SYN,ACK"), "flow keeps the union of TCP flags");
        check(Packet.flagNames(0x3f).equals("FIN,SYN,RST,PSH,ACK,URG") && Packet.flagNames(0).isEmpty(), "flag names");

        Analyzer demo = new Analyzer(12, 10 * S);
        PcapReader.read(EXAMPLES.resolve("demo.pcap"), demo::accept);
        check(demo.flows().size() == 19 && demo.alerts().size() == 1 && demo.alerts().get(0).source().equals("192.0.2.20"), "demo: 19 flows, one alert from 192.0.2.20");
        Analyzer slow = new Analyzer(12, 10 * S);
        PcapReader.read(EXAMPLES.resolve("slow-diverse.pcap"), slow::accept);
        check(slow.flows().size() == 20 && slow.alerts().isEmpty(), "slow-diverse negative control: 20 flows, no alert");

        invalidArg(() -> new Analyzer(1, S), "threshold below 2");
        invalidArg(() -> new Analyzer(65_537, S), "threshold above 65536");
        invalidArg(() -> new Analyzer(12, 0), "zero window");
        invalidArg(() -> new Analyzer(12, 86_401 * S), "window above one day");
        check(Main.windowNanos("0.5") == 500_000_000L && Main.windowNanos("10") == 10 * S && Main.windowNanos("86400") == 86_400 * S, "window parsed exactly");
        for (String bad : List.of("0", "-1", "abc", "NaN", "Infinity", "1e-12", "86400.5")) invalidArg(() -> Main.windowNanos(bad), "invalid window " + bad);
    }

    private static void limits() {
        Analyzer a = new Analyzer(12, 10 * S);
        for (int i = 0; i < Analyzer.MAX_FLOWS + 5; i++) a.accept(new Packet(i, "a", "b", Packet.UDP, 1 + i / 65_000, 1 + i % 65_000, 0, 60));
        check(a.flows().size() == Analyzer.MAX_FLOWS && a.untrackedPackets() == 5, "flow limit keeps analysing and counts untracked packets");
        a.accept(new Packet(Long.MAX_VALUE / 2, "a", "b", Packet.UDP, 1, 1, 0, 60));
        check(a.untrackedPackets() == 5, "existing flows keep counting after the limit");
        a = new Analyzer(12, 10 * S);
        for (int i = 0; i < Analyzer.MAX_PAIRS + 3; i++) a.accept(syn(0, "s" + i, "d", 80));
        check(a.unevaluatedSyns() == 3, "pair limit counts unevaluated SYNs");
        for (int i = 0; i < 1024; i++) a.accept(syn(20 * S, "late", "d", 80));
        check(a.unevaluatedSyns() == 3, "stale pairs are swept so new pairs are tracked again");
        a = new Analyzer(65_536, 10 * S);
        for (int port = 0; port < 65_536; port++) a.accept(syn(port, "a", "b", port));
        check(a.alerts().size() == 1 && a.alerts().get(0).distinctPorts() == 65_536 && a.alerts().get(0).samplePorts().size() == 20, "every port can be counted; sample capped at 20");
    }

    private static void reportFormats() throws IOException {
        check(Report.escapeHtml("<img>&\"'").equals("&lt;img&gt;&amp;&quot;&#39;"), "HTML escaping");
        check(Report.quote("\"\\\n\t\u0001").equals("\"\\\"\\\\\\n\\t\\u0001\""), "JSON escaping");
        check(Report.csvField("SYN,ACK").equals("\"SYN,ACK\"") && Report.csvField("SYN").equals("SYN"), "CSV quoting");
        check(Report.utc(Fixtures.BASE + 250_000_000L).equals("2023-11-14T22:13:20.250Z") && Report.epoch(Fixtures.BASE + 5).equals("1700000000.000000005"), "time formatting");
        check(Report.seconds(10 * S).equals("10") && Report.seconds(500_000_000L).equals("0.5"), "window formatting");

        Analyzer a = new Analyzer(12, 10 * S);
        var summary = PcapReader.read(EXAMPLES.resolve("demo.pcap"), a::accept);
        var result = new Report.Result("<script>x</script>.pcap", Main.VERSION, summary, a);
        String html = Report.html(result, 2);
        check(!html.contains("<script>") && html.contains("&lt;script&gt;"), "hostile file name escaped in HTML");
        check(html.contains("Showing 2 of 19 flows") && html.split("<tr>").length == 4, "HTML preview bounded and says so");
        check(html.indexOf("192.0.2.5:44000") < html.indexOf("192.0.2.7:44000"), "preview orders flows by packets, ties by first seen");
        Object json = new MiniJson(Report.json(result)).parse();
        check(json instanceof Map<?, ?> m && m.get("alerts") instanceof List<?> l && l.size() == 1, "JSON parses and lists alerts");
        @SuppressWarnings("unchecked") Map<String, Object> coverage = (Map<String, Object>) ((Map<?, ?>) json).get("coverage");
        check(coverage.get("decoded").equals(33.0), "JSON coverage numbers");
        String csv = Report.csv(a);
        List<String> lines = csv.lines().toList();
        check(lines.size() == 20 && lines.stream().allMatch(l -> splitCsv(l).size() == 13), "CSV: header plus one 13-field row per flow");

        Analyzer empty = new Analyzer(12, 10 * S);
        Path p = dir.resolve("empty.pcap");
        Fixtures.write(p, List.of(), ByteOrder.LITTLE_ENDIAN, false);
        String emptyJson = Report.json(new Report.Result("empty.pcap", Main.VERSION, PcapReader.read(p, empty::accept), empty));
        new MiniJson(emptyJson).parse();
        check(emptyJson.contains("\"first\":null") && emptyJson.contains("\"alerts\":[]"), "empty capture JSON is valid with null times");
    }

    private static List<String> splitCsv(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean quoted = false;
        for (char c : line.toCharArray()) {
            if (c == '"') quoted = !quoted;
            else if (c == ',' && !quoted) { fields.add(cur.toString()); cur.setLength(0); }
            else cur.append(c);
        }
        fields.add(cur.toString());
        return fields;
    }

    private static void cliBehaviour() throws IOException {
        Path reports = dir.resolve("reports");
        var demo = cli("examples/demo.pcap", reports.resolve("demo").toString());
        check(demo.code() == 0 && demo.out().contains("RECORDS=33 DECODED=33 FLOWS=19 ALERTS=1") && demo.out().contains("ALERT   192.0.2.20 -> 198.51.100.10"), "demo exits 0 and prints the alert");
        for (String f : List.of("report.html", "flows.csv", "summary.json")) check(Files.isRegularFile(reports.resolve("demo").resolve(f)), "writes " + f);
        new MiniJson(Files.readString(reports.resolve("demo/summary.json"))).parse();
        check(cli("examples/demo.pcap", reports.resolve("d2").toString(), "--fail-on-alert").code() == 1, "--fail-on-alert exits 1 when alerts exist");
        check(cli("examples/slow-diverse.pcap", reports.resolve("slow").toString(), "--fail-on-alert").code() == 0, "--fail-on-alert exits 0 without alerts");
        check(cli("examples/slow-diverse.pcap", reports.resolve("slow2").toString(), "--threshold", "3", "--window", "60", "--fail-on-alert").code() == 1, "custom threshold and window change the outcome");
        var coverage = cli("examples/coverage.pcap", reports.resolve("coverage").toString());
        check(coverage.code() == 0 && coverage.out().contains("Linux cooked capture") && coverage.out().lines().filter(l -> l.startsWith("NOTE")).count() == 6, "coverage example prints six notes");
        check(cli("examples/demo.pcap", reports.resolve("rows").toString(), "--html-rows", "0").code() == 0
                && Files.readString(reports.resolve("rows/report.html")).contains("Showing 0 of 19"), "--html-rows 0 hides the table");

        Path fresh = reports.resolve("never-created");
        Path junk = Files.writeString(dir.resolve("junk.pcap"), "not a capture");
        check(cli(junk.toString(), fresh.toString()).code() == 2 && !Files.exists(fresh), "invalid input exits 2 and writes nothing");
        check(cli("does-not-exist.pcap", reports.resolve("x").toString()).code() == 2, "missing capture exits 2");
        check(cli("examples", reports.resolve("x").toString()).code() == 2, "directory as capture exits 2");
        check(cli("examples/demo.pcap", reports.resolve("x").toString(), "--threshold", "1").code() == 2, "bad threshold exits 2");
        check(cli("examples/demo.pcap", reports.resolve("x").toString(), "--threshold", "many").code() == 2, "non-numeric threshold exits 2");
        check(cli("examples/demo.pcap", reports.resolve("x").toString(), "--window", "0").code() == 2, "bad window exits 2");
        check(cli("examples/demo.pcap", reports.resolve("x").toString(), "--html-rows", "-1").code() == 2, "negative html rows exits 2");
        check(cli("examples/demo.pcap", reports.resolve("x").toString(), "--window").code() == 2, "missing option value exits 2");
        check(cli("examples/demo.pcap", reports.resolve("x").toString(), "--nope").code() == 2, "unknown option exits 2");
        check(cli("examples/demo.pcap").code() == 2 && cli().code() == 2, "wrong argument count exits 2");
        check(cli("examples/demo.pcap", junk.resolve("sub").toString()).code() == 2, "unwritable report directory exits 2");

        check(cli("--help").code() == 0 && cli("--help").out().contains("Usage:"), "--help prints usage");
        check(cli("--version").out().trim().equals("TraceLens " + Main.VERSION), "--version");
        check(Files.readString(Path.of("pom.xml")).contains("<version>" + Main.VERSION + "</version>"), "pom.xml version matches Main.VERSION");
    }

    /** Minimal strict JSON parser, used only to prove the generated reports are valid JSON. */
    private static final class MiniJson {
        private final String s; private int i;
        MiniJson(String s) { this.s = s; }
        Object parse() {
            Object v = value(); ws();
            if (i != s.length()) throw new AssertionError("trailing JSON data at " + i);
            return v;
        }
        private void ws() { while (i < s.length() && " \n\r\t".indexOf(s.charAt(i)) >= 0) i++; }
        private char peek() { if (i >= s.length()) throw new AssertionError("unexpected end of JSON"); return s.charAt(i); }
        private void expect(char c) { if (peek() != c) throw new AssertionError("expected '" + c + "' at " + i); i++; }
        private Object value() {
            ws();
            char c = peek();
            if (c == '{') {
                i++; Map<String, Object> m = new LinkedHashMap<>(); ws();
                if (peek() == '}') { i++; return m; }
                while (true) { ws(); String k = string(); ws(); expect(':'); m.put(k, value()); ws(); if (peek() == ',') { i++; continue; } expect('}'); return m; }
            }
            if (c == '[') {
                i++; List<Object> l = new ArrayList<>(); ws();
                if (peek() == ']') { i++; return l; }
                while (true) { l.add(value()); ws(); if (peek() == ',') { i++; continue; } expect(']'); return l; }
            }
            if (c == '"') return string();
            for (String lit : new String[] {"true", "false", "null"}) if (s.startsWith(lit, i)) { i += lit.length(); return lit; }
            int start = i;
            while (i < s.length() && "-+0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            if (start == i) throw new AssertionError("bad JSON value at " + i);
            return Double.valueOf(s.substring(start, i));
        }
        private String string() {
            expect('"'); StringBuilder b = new StringBuilder();
            while (peek() != '"') {
                char c = s.charAt(i++);
                if (c < 32) throw new AssertionError("raw control character in JSON string");
                if (c == '\\') {
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"', '\\', '/' -> b.append(e);
                        case 'n' -> b.append('\n'); case 'r' -> b.append('\r'); case 't' -> b.append('\t');
                        case 'b' -> b.append('\b'); case 'f' -> b.append('\f');
                        case 'u' -> { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                        default -> throw new AssertionError("bad escape");
                    }
                } else b.append(c);
            }
            i++; return b.toString();
        }
    }
}
