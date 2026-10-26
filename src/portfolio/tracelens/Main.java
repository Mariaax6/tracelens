package portfolio.tracelens;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public final class Main {
    static String esc(String s) { return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;"); }
    public static void main(String[] args) {
        if(args.length==1 && args[0].equals("--help")) {
            System.out.println("TraceLens: java -jar tracelens.jar <capture.pcap> <report-directory> [distinct-ports=12] [window-seconds=10]"); return;
        }
        try {
            if(args.length<2 || args.length>4) throw new IllegalArgumentException("Use --help for usage");
            Analyzer a=new Analyzer(args.length>2?Integer.parseInt(args[2]):12,args.length>3?Double.parseDouble(args[3]):10);
            PcapReader.Summary s=PcapReader.read(Path.of(args[0]),a::accept);
            Path out=Path.of(args[1]); Files.createDirectories(out);
            StringBuilder csv=new StringBuilder("source,destination,protocol,source_port,destination_port,packets,wire_bytes,first,last\n");
            StringBuilder rows=new StringBuilder();
            for(var e:a.flows().entrySet()) {
                var k=e.getKey(); var f=e.getValue();
                csv.append(String.format(Locale.ROOT,"%s,%s,%d,%d,%d,%d,%d,%.6f,%.6f%n",k.source(),k.destination(),k.protocol(),k.sourcePort(),k.destinationPort(),f.packets,f.bytes,f.first,f.last));
                if(rows.length()<150_000) rows.append("<tr><td>").append(k.source()).append(":").append(k.sourcePort()).append("</td><td>").append(k.destination()).append(":").append(k.destinationPort()).append("</td><td>").append(k.protocol()==6?"TCP":k.protocol()==17?"UDP":"ICMP").append("</td><td>").append(f.packets).append("</td><td>").append(f.bytes).append("</td></tr>");
            }
            StringBuilder alertRows=new StringBuilder();
            for(var v:a.alerts()) alertRows.append("<li><strong>").append(v.source()).append(" → ").append(v.destination()).append("</strong>: ").append(v.ports()).append(" ports. ").append(esc(v.reason())).append("</li>");
            String html="""
                <!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
                <title>TraceLens · Network evidence</title><style>
                body{font:16px system-ui;background:#0c1424;color:#e4ecfa;max-width:1150px;margin:45px auto;padding:0 22px}h1{font-size:46px;margin-bottom:0}small{color:#92b9d6}section{background:#152238;border:1px solid #2d4563;border-radius:14px;padding:24px;margin:22px 0}.metrics{display:flex;gap:35px;flex-wrap:wrap}.metrics b{font-size:32px;display:block;color:#69e0c2}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #2d4563}li{margin:16px 0}code{color:#69e0c2}p{line-height:1.6}footer{color:#a6b8d0}
                </style><small>NETWORKS / SYSTEMS / SECURITY</small><h1>TraceLens</h1><p>Offline packet evidence, understandable findings.</p>
                """+
                "<section class=metrics><div><b>"+s.records()+"</b>Records</div><div><b>"+s.decoded()+"</b>Decoded</div><div><b>"+a.flows().size()+"</b>Directional flows</div><div><b>"+a.alerts().size()+"</b>SYN-pattern alerts</div></section>"+
                "<section><h2>Capture coverage</h2><p>Input: "+esc(Path.of(args[0]).getFileName().toString())+"</p><p>Unsupported: "+s.unsupported()+" · Malformed/incomplete: "+s.malformed()+" · Fragments skipped: "+s.fragments()+" · Snaplen-truncated records: "+s.truncated()+"</p><p>These categories overlap for truncation. Zero alerts does not mean a safe network.</p></section>"+
                "<section><h2>Investigation queue</h2><p>Threshold: "+a.threshold()+" distinct destination ports in "+a.windowSeconds()+" seconds, per source/destination pair. Retransmissions to one port do not increase diversity.</p><ul>"+(alertRows.isEmpty()?"<li>No threshold crossings.</li>":alertRows)+"</ul></section>"+
                "<section><h2>Directional flows</h2><p>HTML is a bounded preview; flows.csv contains every aggregated flow. Protocol numbers: TCP 6, UDP 17, ICMP 1.</p><div style=overflow:auto><table><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Wire bytes</th></tr>"+rows+"</table></div></section><footer>Classic PCAP · Ethernet/VLAN · IPv4 · No payload inspection, decryption or live capture. Synthetic demo traffic is labelled in the README.</footer></html>";
            Files.writeString(out.resolve("flows.csv"),csv);
            Files.writeString(out.resolve("report.html"),html);
            Files.writeString(out.resolve("summary.json"),"{\"records\":"+s.records()+",\"decoded\":"+s.decoded()+",\"unsupported\":"+s.unsupported()+",\"malformed\":"+s.malformed()+",\"fragments\":"+s.fragments()+",\"truncated\":"+s.truncated()+",\"flows\":"+a.flows().size()+",\"alerts\":"+a.alerts().size()+"}\n");
            System.out.println("Decoded "+s.decoded()+" / "+s.records()+" records; "+a.flows().size()+" flows; "+a.alerts().size()+" alerts. Report: "+out.toAbsolutePath().resolve("report.html"));
        } catch(IOException|IllegalArgumentException|IllegalStateException e) {
            System.err.println("TraceLens: "+e.getMessage()); System.exit(2);
        }
    }
}
