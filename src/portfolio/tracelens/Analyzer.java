package portfolio.tracelens;

import java.util.*;

/** Directional flow aggregation and a bounded, time-window SYN heuristic. */
public final class Analyzer {
    public record Key(String source,String destination,int protocol,int sourcePort,int destinationPort) {}
    public static final class Flow {
        public long packets, bytes;
        public double first,last;
        Flow(double time) { first=last=time; }
    }
    public record Alert(String source,String destination,double time,int ports,String reason) {}
    private record Attempt(double time,int port) {}
    private final Map<Key,Flow> flows=new LinkedHashMap<>();
    private static final class Window {
        final ArrayDeque<Attempt> attempts=new ArrayDeque<>();
        final Map<Integer,Integer> counts=new HashMap<>();
    }
    private final Map<String,Window> windows=new HashMap<>();
    private final Map<String,Double> lastAlert=new HashMap<>();
    private final List<Alert> alerts=new ArrayList<>();
    private final int threshold;
    private final double windowSeconds;
    private long synCount;
    public Analyzer(int threshold,double windowSeconds) {
        if(threshold<2 || !Double.isFinite(windowSeconds) || windowSeconds<=0) throw new IllegalArgumentException("Invalid detection parameters");
        this.threshold=threshold; this.windowSeconds=windowSeconds;
    }
    public void accept(PcapReader.Packet p) {
        Key k=new Key(p.source(),p.destination(),p.protocol(),p.sourcePort(),p.destinationPort());
        if(!flows.containsKey(k) && flows.size()>=100_000) throw new IllegalStateException("Safety limit: 100,000 directional flows");
        Flow f=flows.computeIfAbsent(k,x->new Flow(p.time()));
        f.packets++; f.bytes+=p.bytes(); f.last=p.time();
        if(p.protocol()!=6 || (p.flags()&0x12)!=0x02) return; // SYN without ACK
        String pair=p.source()+">"+p.destination();
        // Periodic global expiry also bounds state for sources which stop transmitting.
        if((++synCount&1023)==0) windows.entrySet().removeIf(e->e.getValue().attempts.peekLast().time()<p.time()-windowSeconds);
        Window w=windows.computeIfAbsent(pair,x->new Window());
        var q=w.attempts;
        q.addLast(new Attempt(p.time(),p.destinationPort()));
        w.counts.merge(p.destinationPort(),1,Integer::sum);
        while(!q.isEmpty() && q.peekFirst().time()<p.time()-windowSeconds) {
            int port=q.removeFirst().port();
            w.counts.compute(port,(key,count)->count==1?null:count-1);
        }
        if(q.size()>100_000) throw new IllegalStateException("Safety limit: 100,000 SYNs per window");
        var ports=w.counts.keySet();
        if(ports.size()>=threshold && p.time()-lastAlert.getOrDefault(pair,Double.NEGATIVE_INFINITY)>=windowSeconds) {
            alerts.add(new Alert(p.source(),p.destination(),p.time(),ports.size(),"Distinct SYN destination ports within "+windowSeconds+" seconds; investigate, not proof of an attack"));
            lastAlert.put(pair,p.time());
        }
    }
    public Map<Key,Flow> flows() { return Collections.unmodifiableMap(flows); }
    public List<Alert> alerts() { return List.copyOf(alerts); }
    public int threshold() { return threshold; }
    public double windowSeconds() { return windowSeconds; }
}
