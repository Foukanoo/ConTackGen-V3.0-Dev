package fr.contacgen;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import io.pkts.PacketHandler;
import io.pkts.packet.Packet;
import io.pkts.protocol.Protocol;

public class ConTacGenPacketHandler implements PacketHandler {
	private static final ConTacGenPacketHandler INSTANCE = new ConTacGenPacketHandler();

	public static final ConTacGenPacketHandler getInstance() {
		return INSTANCE;
	}

	private List<PacketData> data = new ArrayList<>();
	private Instant startTime = Instant.now().minus(Duration.ofSeconds(5));

	private ConTacGenPacketHandler() {}

	@Override
	public boolean nextPacket(Packet packet) throws IOException {
		if(!packet.hasProtocol(Protocol.IPv4) && !packet.hasProtocol(Protocol.IPv6)) return true;
		// Update the timer
		long timeDiffInMillis = packet.getArrivalTime() / 1000 - startTime.toEpochMilli();
		data.add(new PacketData(packet, timeDiffInMillis));
		return true;
	}

	public ConTacGenPacketHandler clear() {
		data.clear();
		return this;
	}
	
	public ConTacGenPacketHandler foreach(Consumer<PacketData> action) {
		data.forEach(action);
		return this;
	}
}
