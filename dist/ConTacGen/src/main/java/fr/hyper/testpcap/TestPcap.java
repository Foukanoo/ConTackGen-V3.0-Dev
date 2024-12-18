package fr.hyper.testpcap;

import java.io.FileNotFoundException;
import java.io.IOException;

import io.pkts.Pcap;

public class TestPcap {

	public static void main(String[] args) throws FileNotFoundException, IOException {
		String pcapFile = args.length > 1 ? args[1] : System.getProperty("java.io.tmpdir") + "/capture.pcap";
		System.out.println("Read pcap file: " + pcapFile + "");

		Pcap pcap = Pcap.openStream(pcapFile);
		
		pcap.loop(new TcpUdpPacketHandler());
		pcap.close();
	}

}
