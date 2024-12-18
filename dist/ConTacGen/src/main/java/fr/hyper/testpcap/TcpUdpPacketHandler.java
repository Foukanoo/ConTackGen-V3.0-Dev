package fr.hyper.testpcap;

import java.io.IOException;

import io.pkts.PacketHandler;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

// https://javahelps.com/how-to-parse-pcap-files-in-java
public class TcpUdpPacketHandler implements PacketHandler {
    @Override
    public boolean nextPacket(Packet packet) throws IOException {
    	System.out.println(packet);
        if (packet.hasProtocol(Protocol.TCP)) {
        	System.out.println("TCP");
            TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);

            Buffer buffer = tcpPacket.getPayload();
            if (buffer != null) {
                System.out.println("TCP: " + buffer);
            }
        } else if (packet.hasProtocol(Protocol.UDP)) {
        	System.out.println("UDP");
            UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);

            Buffer buffer = udpPacket.getPayload();
            if (buffer != null) {
                System.out.println("UDP: " + buffer);
            }
        } else if(packet.hasProtocol(Protocol.IPv4)) {
        	System.out.println("IP4");
        } else if(packet.hasProtocol(Protocol.IPv6)) {
        	System.out.println("IP6");
        }
/**
     * Return true if you want to keep receiving next packet.
     * Return false if you want to stop traversal
     */
        return true;
    }
}
