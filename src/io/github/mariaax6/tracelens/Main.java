package io.github.mariaax6.tracelens;

import java.io.IOException;
import java.io.PrintStream;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Command-line entry point. All logic lives in {@link #run} so tests can call it without System.exit. */
public final class Main {
    private Main() {}

    public static final String VERSION = "2.0.0";
    static final int DEFAULT_THRESHOLD = 12;
    static final String DEFAULT_WINDOW = "10";
    static final int DEFAULT_HTML_ROWS = 500;

    static final String USAGE = """
        TraceLens %s - offline PCAP flow analyser

        Usage:
          java -jar tracelens.jar <capture.pcap> <report-dir> [options]

        Options:
          --threshold <ports>   Distinct SYN destination ports that raise an alert (2-65536, default 12)
          --window <seconds>    Sliding window length (default 10, maximum 86400)
          --html-rows <n>       Flows shown in report.html (default 500; flows.csv always has all)
          --fail-on-alert       Exit with code 1 when any alert is raised
          --version             Print the version and exit
          -h, --help            Show this help

        Reads classic PCAP (not PCAPNG) with Ethernet, Linux SLL or raw IPv4 link types.
        Writes report.html, flows.csv and summary.json.
        Exit codes: 0 analysis completed; 1 alerts with --fail-on-alert; 2 invalid input or usage.
        """.formatted(VERSION);

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        try {
            List<String> positional = new ArrayList<>();
            int threshold = DEFAULT_THRESHOLD, htmlRows = DEFAULT_HTML_ROWS;
            String window = DEFAULT_WINDOW;
            boolean failOnAlert = false;
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "-h", "--help" -> { out.print(USAGE); return 0; }
                    case "--version" -> { out.println("TraceLens " + VERSION); return 0; }
                    case "--fail-on-alert" -> failOnAlert = true;
                    case "--threshold" -> threshold = parseInt(value(args, ++i, arg), arg);
                    case "--window" -> window = value(args, ++i, arg);
                    case "--html-rows" -> {
                        htmlRows = parseInt(value(args, ++i, arg), arg);
                        if (htmlRows < 0) throw new IllegalArgumentException("--html-rows must be 0 or more");
                    }
                    default -> {
                        if (arg.startsWith("-")) throw new IllegalArgumentException("Unknown option: " + arg + ". Use --help for usage");
                        positional.add(arg);
                    }
                }
            }
            if (positional.size() != 2) throw new IllegalArgumentException("Expected <capture.pcap> and <report-dir>. Use --help for usage");
            Path input = Path.of(positional.get(0));
            if (!Files.isRegularFile(input)) throw new IOException("Capture file does not exist: " + input);

            Analyzer analyzer = new Analyzer(threshold, windowNanos(window));
            PcapReader.Summary summary = PcapReader.read(input, analyzer::accept);
            Path name = input.getFileName();
            Report.Result result = new Report.Result(name == null ? input.toString() : name.toString(), VERSION, summary, analyzer);

            Path reportDir = Path.of(positional.get(1));
            Files.createDirectories(reportDir);
            Files.writeString(reportDir.resolve("flows.csv"), Report.csv(analyzer));
            Files.writeString(reportDir.resolve("summary.json"), Report.json(result));
            Files.writeString(reportDir.resolve("report.html"), Report.html(result, htmlRows));

            out.printf("TraceLens %s | input=%s | %s%n", VERSION, result.inputName(), PcapReader.linkTypeName(summary.linkType()));
            out.printf("RECORDS=%d DECODED=%d FLOWS=%d ALERTS=%d%n", summary.records(), summary.decoded(), analyzer.flows().size(), analyzer.alerts().size());
            for (var a : analyzer.alerts()) {
                out.printf("ALERT   %s -> %s at %s: %d distinct SYN ports (%s)%n", a.source(), a.destination(),
                        Report.utc(a.timeNanos()), a.distinctPorts(), Report.portSummary(a));
            }
            for (String w : Report.warnings(result)) out.println("NOTE    " + w);
            out.println("Report: " + reportDir.toAbsolutePath().resolve("report.html"));
            return failOnAlert && !analyzer.alerts().isEmpty() ? 1 : 0;
        } catch (IOException | IllegalArgumentException e) {
            err.println("TraceLens: " + e.getMessage());
            return 2;
        }
    }

    private static String value(String[] args, int index, String option) {
        if (index >= args.length) throw new IllegalArgumentException("Option " + option + " needs a value");
        return args[index];
    }

    private static int parseInt(String text, String option) {
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(option + " must be a whole number");
        }
    }

    /** Parses decimal seconds exactly (no floating point) and converts to nanoseconds. */
    static long windowNanos(String text) {
        BigDecimal seconds;
        try {
            seconds = new BigDecimal(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("--window must be a number of seconds");
        }
        if (seconds.signum() <= 0 || seconds.compareTo(BigDecimal.valueOf(86_400)) > 0) {
            throw new IllegalArgumentException("Window must be greater than 0 and at most 86400 seconds");
        }
        long nanos = seconds.movePointRight(9).setScale(0, RoundingMode.HALF_UP).longValueExact();
        if (nanos <= 0) throw new IllegalArgumentException("Window is shorter than one nanosecond");
        return nanos;
    }
}
