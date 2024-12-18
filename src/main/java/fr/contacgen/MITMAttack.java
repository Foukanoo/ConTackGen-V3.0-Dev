package fr.contacgen;

import java.io.*;
import java.net.*;

public class MITMAttack implements Runnable {
    private int proxyPort;
    private String serverAddress;
    private int serverPort;
    private int duration; 
    private volatile boolean running = true;

    public MITMAttack(String serverAddress, int serverPort, int proxyPort, int duration) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.proxyPort = proxyPort;
        this.duration = duration;
    }

    public void stop() {
        running = false;
    }

    @Override
    public void run() {
        System.out.println("MITM Attack started on port " + proxyPort + " targeting " + serverAddress + ":" + serverPort);
        long startTime = System.currentTimeMillis();

        try (ServerSocket proxySocket = new ServerSocket(proxyPort)) {
            proxySocket.setSoTimeout(2000); 
            while (running && ((System.currentTimeMillis() - startTime) < duration * 1000)) {
                try {
                    Socket clientSocket = proxySocket.accept();
                    handleClientConnection(clientSocket);
                } catch (SocketTimeoutException e) {
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("MITM Attack stopped.");
    }

    private void handleClientConnection(Socket clientSocket) throws IOException {
        try (
            BufferedReader clientIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter clientOut = new PrintWriter(clientSocket.getOutputStream(), true);
            Socket serverSocket = new Socket(serverAddress, serverPort);
            BufferedReader serverIn = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
            PrintWriter serverOut = new PrintWriter(serverSocket.getOutputStream(), true)
        ) {
            String clientMessage = clientIn.readLine();
            if (clientMessage != null) {
                System.out.println("MITM intercepted from client: " + clientMessage);
                String modifiedMessage = clientMessage.replace("Client", "Attack");
                System.out.println("MITM modified message: " + modifiedMessage);

                serverOut.println(modifiedMessage);

                String serverResponse = serverIn.readLine();
                System.out.println("MITM intercepted from server: " + serverResponse);

                clientOut.println(serverResponse);
            }
        } finally {
            clientSocket.close();
        }
    }

    public static void main(String[] args) {
        MITMAttack mitm = new MITMAttack("localhost", 8080, 9090, 60);
        new Thread(mitm).start();
    }
}
