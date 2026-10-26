package portfolio.tracelens;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;

/** Deterministic synthetic Ethernet/IPv4 packets; never opens a socket. */
public final class Demo {
    public record Frame(double time,byte[] data) {}
    public static byte[] packet(int proto,int sourceHost,int destinationPort,int flags) {
        int transport=proto==6?20:8;
        byte[] b=new byte[14+20+transport];
        Arrays.fill(b,0,6,(byte)0x22); Arrays.fill(b,6,12,(byte)0x44);
        b[12]=8; b[14]=0x45;
        put16(b,16,20+transport); b[22]=64; b[23]=(byte)proto;
        b[26]=(byte)192;b[27]=0;b[28]=2;b[29]=(byte)sourceHost;
        b[30]=(byte)198;b[31]=51;b[32]=100;b[33]=10;
        if(proto==6 || proto==17) { put16(b,34,44000); put16(b,36,destinationPort); }
        if(proto==6) { b[46]=0x50; b[47]=(byte)flags; put16(b,48,65535); }
        else if(proto==17) put16(b,38,8);
        else b[34]=8;
        // Valid IPv4 checksum; TCP checksum includes pseudoheader. UDP zero means unused in IPv4.
        put16(b,24,checksum(b,14,20,0));
        if(proto==6) {
            int sum=proto+transport;
            for(int i=26;i<34;i+=2) sum+=((b[i]&255)<<8)|(b[i+1]&255);
            put16(b,50,checksum(b,34,transport,sum));
        } else if(proto==1) put16(b,36,checksum(b,34,transport,0));
        return b;
    }
    static void put16(byte[] b,int i,int v) { b[i]=(byte)(v>>>8); b[i+1]=(byte)v; }
    static int checksum(byte[] b,int start,int length,int sum) {
        for(int i=start;i<start+length;i+=2) sum+=((b[i]&255)<<8)|(i+1<start+length?b[i+1]&255:0);
        while((sum>>>16)!=0) sum=(sum&65535)+(sum>>>16);
        return (~sum)&65535;
    }
    public static void write(Path path,List<Frame> frames,ByteOrder order,boolean nano) throws IOException {
        try(OutputStream out=Files.newOutputStream(path)) {
            ByteBuffer h=ByteBuffer.allocate(24).order(order);
            h.putInt(nano?0xa1b23c4d:0xa1b2c3d4).putShort((short)2).putShort((short)4).putInt(0).putInt(0).putInt(65535).putInt(1);
            out.write(h.array());
            for(Frame f:frames) {
                long sec=(long)f.time(); int fraction=(int)Math.round((f.time()-sec)*(nano?1e9:1e6));
                ByteBuffer r=ByteBuffer.allocate(16).order(order);
                r.putInt((int)sec).putInt(fraction).putInt(f.data().length).putInt(f.data().length);
                out.write(r.array());out.write(f.data());
            }
        }
    }
    public static void main(String[] args) throws IOException {
        Path dir=Path.of(args.length==0?"examples":args[0]);Files.createDirectories(dir);
        List<Frame> frames=new ArrayList<>();
        for(int i=0;i<8;i++) frames.add(new Frame(1700000000+i*.25,packet(17,5,53,0)));
        for(int i=0;i<16;i++) frames.add(new Frame(1700000003+i*.2,packet(6,20,1000+i,2)));
        for(int i=0;i<8;i++) frames.add(new Frame(1700000008+i*.1,packet(6,7,443,2)));
        frames.add(new Frame(1700000010,packet(1,5,0,0)));
        write(dir.resolve("demo.pcap"),frames,ByteOrder.LITTLE_ENDIAN,false);
        List<Frame> benign=new ArrayList<>();
        for(int i=0;i<20;i++) benign.add(new Frame(1700000000+i*11,packet(6,5,1000+i,2)));
        write(dir.resolve("slow-diverse.pcap"),benign,ByteOrder.BIG_ENDIAN,true);
        System.out.println("Synthetic fixtures: demo.pcap (33 records, 1 alert); slow-diverse.pcap (20 records, 0 alerts)");
    }
}
