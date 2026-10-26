package portfolio.tracelens;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
public final class Tests {
    static int checks;
    static void check(boolean condition,String label) { checks++;if(!condition) throw new AssertionError(label); }
    static void invalid(Path p,String label) throws Exception {
        try { PcapReader.read(p,x->{}); throw new AssertionError(label); } catch(IOException expected) { checks++; }
    }
    public static void main(String[] args) throws Exception {
        Path dir=Files.createTempDirectory("tracelens-tests-");
        try {
            for(ByteOrder order:List.of(ByteOrder.LITTLE_ENDIAN,ByteOrder.BIG_ENDIAN)) for(boolean nano:List.of(false,true)) {
                Path p=dir.resolve("endian.pcap");
                Demo.write(p,List.of(new Demo.Frame(100.25,Demo.packet(6,4,443,2))),order,nano);
                List<PcapReader.Packet> packets=new ArrayList<>(); var summary=PcapReader.read(p,packets::add);
                check(summary.decoded()==1,"all endian/timestamp variants");
                check(packets.get(0).destinationPort()==443 && packets.get(0).time()==100.25,"ports and timestamp");
            }
            Analyzer a=new Analyzer(12,10);
            for(int i=0;i<40;i++) a.accept(new PcapReader.Packet(i*.01,"a","b",6,4000,22,2,54));
            check(a.alerts().isEmpty(),"retransmission deduplication");
            for(int i=0;i<11;i++) a.accept(new PcapReader.Packet(1+i*.01,"a","b",6,4000,100+i,2,54));
            check(a.alerts().size()==1,"distinct ports threshold");
            check(a.flows().values().stream().mapToLong(f->f.packets).sum()==51,"flow aggregation conserves records");
            a=new Analyzer(3,10);
            for(int i=0;i<6;i++) a.accept(new PcapReader.Packet(i*11,"a","b",6,4000,100+i,2,54));
            check(a.alerts().isEmpty(),"window expiration");
            a=new Analyzer(3,10);
            for(int i=0;i<10;i++) a.accept(new PcapReader.Packet(i,"a","b",6,4000,100+i,0x12,54));
            check(a.alerts().isEmpty(),"SYN-ACK excluded");
            Path p=dir.resolve("bad.pcap");Files.write(p,new byte[12]);invalid(p,"short global header");
            Demo.write(p,List.of(new Demo.Frame(2,Demo.packet(17,4,53,0))),ByteOrder.LITTLE_ENDIAN,false);
            byte[] raw=Files.readAllBytes(p);Files.write(p,Arrays.copyOf(raw,raw.length-1)); invalid(p,"truncated record");
            ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putInt(32,1000000);Files.write(p,raw);invalid(p,"oversized record");
            Demo.write(p,List.of(new Demo.Frame(2,Demo.packet(6,4,22,2)),new Demo.Frame(1,Demo.packet(6,4,23,2))),ByteOrder.LITTLE_ENDIAN,false);
            invalid(p,"unordered timestamps");
            byte[] fragmented=Demo.packet(6,4,22,2);fragmented[20]=0x20;
            Demo.write(p,List.of(new Demo.Frame(2,fragmented)),ByteOrder.BIG_ENDIAN,false);
            check(PcapReader.read(p,x->{throw new AssertionError();}).fragments()==1,"fragment skip");
            byte[] arp=Demo.packet(6,4,22,2);arp[13]=6;
            Demo.write(p,List.of(new Demo.Frame(2,arp)),ByteOrder.BIG_ENDIAN,false);
            check(PcapReader.read(p,x->{}).unsupported()==1,"unsupported EtherType");
            byte[] base=Demo.packet(6,4,443,2),vlan=new byte[base.length+4];
            System.arraycopy(base,0,vlan,0,12);vlan[12]=(byte)0x81;vlan[15]=1;vlan[16]=8;System.arraycopy(base,14,vlan,18,base.length-14);
            Demo.write(p,List.of(new Demo.Frame(2,vlan)),ByteOrder.LITTLE_ENDIAN,false);
            check(PcapReader.read(p,x->{}).decoded()==1,"802.1Q VLAN");
            byte[] badTcp=Demo.packet(6,4,22,2);badTcp[46]=0x10;
            Demo.write(p,List.of(new Demo.Frame(2,badTcp)),ByteOrder.BIG_ENDIAN,false);
            check(PcapReader.read(p,x->{}).malformed()==1,"invalid TCP data offset");
            Demo.write(p,List.of(new Demo.Frame(2,Demo.packet(6,4,22,2))),ByteOrder.LITTLE_ENDIAN,false);
            raw=Files.readAllBytes(p);ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putInt(36,-1);Files.write(p,raw);
            List<PcapReader.Packet> decoded=new ArrayList<>();PcapReader.read(p,decoded::add);
            check(decoded.get(0).bytes()==4294967295L,"wire length is unsigned, not a negative int");
            Demo.write(p,List.of(new Demo.Frame(2,Demo.packet(6,4,22,2))),ByteOrder.LITTLE_ENDIAN,false);
            raw=Files.readAllBytes(p);ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putInt(28,1000000);Files.write(p,raw);
            invalid(p,"invalid timestamp fraction");
            check(Main.esc("<script>\"&").equals("&lt;script&gt;&quot;&amp;"),"HTML escaping");
            System.out.println("TraceLens: "+checks+" checks passed");
        } finally { try(var files=Files.walk(dir)) { for(Path p:files.sorted(Comparator.reverseOrder()).toList()) Files.delete(p); } }
    }
}
