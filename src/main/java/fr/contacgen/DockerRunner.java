package fr.contacgen;

import static fr.contacgen.ConTacGenUtils.dockerContainerExists;
import static fr.contacgen.ConTacGenUtils.dockerCp;
import static fr.contacgen.ConTacGenUtils.dockerExec;
import static fr.contacgen.ConTacGenUtils.dockerImageExists;
import static fr.contacgen.ConTacGenUtils.dockerInspectIP;
import static fr.contacgen.ConTacGenUtils.dockerPull;
import static fr.contacgen.ConTacGenUtils.dockerRm;
import static fr.contacgen.ConTacGenUtils.dockerRun;
import static fr.contacgen.ConTacGenUtils.dockerStop;
import static fr.contacgen.ConTacGenUtils.getDockerClient;
import static fr.contacgen.ConTacGenUtils.readPcap;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.function.Consumer;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback.Adapter;
import com.github.dockerjava.api.model.Frame;

public class DockerRunner {

    private static String attackType = "UDPDOS"; // Par défaut

    private DockerRunner() {}

    /**
     * Définir le type d'attaque (UDPDOS ou MITM)
     */
    public static void setAttackType(String type) {
        attackType = type;
    }

    public static ConTacGenPacketHandler dockerMain(String dockerImage, Consumer<InetAddress> toRun, int duration) throws InterruptedException, IOException {
        File tmpFile = new File(System.getProperty("java.io.tmpdir") + "/capture.pcap");
        System.out.println("Run Docker");

        String containerName = "wekacontacgen";
        String containerFile = "/data/capture.pcap";

        System.out.println("Get Docker client");
        DockerClient dockerClient = getDockerClient();
        if(dockerClient == null)
            throw new IllegalStateException("Could not connect to docker !");

        if (dockerContainerExists(containerName, dockerClient)) {
            System.out.println("Container already exists, stopping and removing");
            dockerStop(containerName, dockerClient);
            dockerRm(containerName, dockerClient);
        }

        if (!dockerImageExists(dockerImage, dockerClient)) {
            dockerPull(dockerImage, dockerClient);
        }

        dockerRun(dockerImage, containerName, dockerClient);

        System.out.println("Set ATTACK_TYPE env to: " + attackType);
        dockerExec("export ATTACK_TYPE="+attackType, containerName, dockerClient).awaitCompletion();

        Adapter<Frame> exec = dockerExec("./payload.sh -d " + duration, containerName, dockerClient);

        String ipAddress = dockerInspectIP(containerName, dockerClient);
        InetAddress address = InetAddress.getByName(ipAddress);

        System.out.println("Start attack code");
        Runnable task = () -> toRun.accept(address);
        Thread attack = new Thread(task);
        attack.start();

        exec.awaitCompletion();
        attack.join();

        // Une fois que c'est fini, on copie le fichier pcap
        dockerCp(tmpFile, containerName, containerFile, dockerClient);

        dockerStop(containerName, dockerClient);
        dockerRm(containerName, dockerClient);

        System.out.println("Stop attack");

        ConTacGenPacketHandler handler = ConTacGenPacketHandler.getInstance();
        handler.clear();

        readPcap(tmpFile, handler);
        tmpFile.delete();
        return handler;
    }
}
