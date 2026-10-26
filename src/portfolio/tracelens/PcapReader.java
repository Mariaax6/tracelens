package portfolio.tracelens;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.function.Consumer;

/** Streaming classic-PCAP reader. No live capture, native library or network access. */
public final class PcapReader {
    public record Packet(double time, String source, String destination, int protocol,
                         int sourcePort, int destinationPort, int flags, long bytes) {}
    public record Summary(long records, long decoded, long unsupported, long malformed,
                          long fragments, long truncated) {}
    private static int u16(byte[] b, int n) { return ((b[n]&255)<<8)|(b[n+1]&255); }
    private static String ip(byte[] b,int n) {
        return (b[n]&255)+"."+(b[n+1]&255)+"."+(b[n+2]&255)+"."+(b[n+3]&255);
    }
    public static Summary read(Path path, Consumer<Packet> sink) throws IOException {
        long records=0, decoded=0, unsupported=0, malformed=0, fragments=0, truncated=0;
        try (InputStream in=new BufferedInputStream(Files.newInputStream(path))) {
            byte[] header=in.readNBytes(24);
            if(header.length!=24) throw new IOException("Truncated PCAP global header");
            int magic=ByteBuffer.wrap(header).getInt();
            boolean nano=magic==0xa1b23c4d || magic==0x4d3cb2a1;
            ByteOrder order=switch(magic) {
                case 0xa1b2c3d4,0xa1b23c4d -> ByteOrder.BIG_ENDIAN;
                case 0xd4c3b2a1,0x4d3cb2a1 -> ByteOrder.LITTLE_ENDIAN;
                default -> throw new IOException("Expected classic PCAP (PCAPNG is not supported)");
            };
            ByteBuffer h=ByteBuffer.wrap(header).order(order);
            if(h.getShort(4)!=2 || h.getShort(6)!=4) throw new IOException("Unsupported PCAP version");
            long snap=Integer.toUnsignedLong(h.getInt(16));
            if(snap==0 || snap>16*1024*1024) throw new IOException("Invalid or excessive snapshot length");
            if(h.getInt(20)!=1) throw new IOException("Only plain Ethernet link type 1 is supported");
            double previous=-1;
            while(true) {
                byte[] rh=in.readNBytes(16);
                if(rh.length==0) break;
                if(rh.length!=16) throw new IOException("Truncated packet record header");
                if(++records>1_000_000) throw new IOException("Safety limit: one million records");
                ByteBuffer r=ByteBuffer.wrap(rh).order(order);
                long seconds=Integer.toUnsignedLong(r.getInt()), fraction=Integer.toUnsignedLong(r.getInt());
                long captured=Integer.toUnsignedLong(r.getInt()), original=Integer.toUnsignedLong(r.getInt());
                if(captured>snap || captured>original) throw new IOException("Invalid captured length at record "+records);
                if(fraction>=(nano?1_000_000_000L:1_000_000L)) throw new IOException("Invalid timestamp fraction");
                double time=seconds+fraction/(nano?1e9:1e6);
                if(time<previous) throw new IOException("Timestamps must be nondecreasing for window detection");
                previous=time;
                byte[] b=in.readNBytes((int)captured);
                if(b.length!=captured) throw new IOException("Truncated packet data at record "+records);
                if(captured<original) truncated++;
                if(b.length<14) { malformed++; continue; }
                int offset=14, ether=u16(b,12), tags=0;
                while((ether==0x8100 || ether==0x88a8) && tags++<2) {
                    if(b.length<offset+4) break;
                    ether=u16(b,offset+2); offset+=4;
                }
                if(ether!=0x0800) { unsupported++; continue; }
                if(b.length<offset+20) { malformed++; continue; }
                int ihl=(b[offset]&15)*4, total=u16(b,offset+2);
                if((b[offset]>>>4 &15)!=4 || ihl<20 || total<ihl || b.length<offset+total) {
                    malformed++; continue;
                }
                if((u16(b,offset+6)&0x3fff)!=0) { fragments++; continue; }
                int proto=b[offset+9]&255, transport=offset+ihl, end=offset+total;
                int sp=0, dp=0, flags=0;
                if(proto==6) {
                    if(end<transport+20) { malformed++; continue; }
                    int tcpHeader=((b[transport+12]>>>4)&15)*4;
                    if(tcpHeader<20 || transport+tcpHeader>end) { malformed++; continue; }
                    sp=u16(b,transport); dp=u16(b,transport+2); flags=b[transport+13]&255;
                } else if(proto==17) {
                    if(end<transport+8 || u16(b,transport+4)<8 || transport+u16(b,transport+4)>end) {
                        malformed++; continue;
                    }
                    sp=u16(b,transport); dp=u16(b,transport+2);
                } else if(proto!=1) { unsupported++; continue; }
                else if(end<transport+8) { malformed++; continue; }
                sink.accept(new Packet(time,ip(b,offset+12),ip(b,offset+16),proto,sp,dp,flags,original));
                decoded++;
            }
        }
        return new Summary(records,decoded,unsupported,malformed,fragments,truncated);
    }
}
