package fr.contacgen;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.List;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.IOUtils;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback.Adapter;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.command.ExecStartCmd;
import com.github.dockerjava.api.command.PullImageResultCallback;
import com.github.dockerjava.api.exception.NotFoundException;
import com.github.dockerjava.api.model.Container;
import com.github.dockerjava.api.model.ContainerNetwork;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.Image;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;
import com.github.dockerjava.transport.DockerHttpClient;

import io.pkts.PacketHandler;
import io.pkts.framer.FramingException;

public class ConTacGenUtils {

	private ConTacGenUtils() {}

	/**
	 * Pull a docker image.
	 * 
	 * @param dockerImage the docker image to pull
	 * @param dockerClient the Docker client
	 * @throws InterruptedException
	 */
	public static void dockerPull(String dockerImage, DockerClient dockerClient) throws InterruptedException {
		System.out.println("Pull image " + dockerImage);
		try {
			dockerClient.pullImageCmd(dockerImage).exec(new PullImageResultCallback()).awaitCompletion();
		} catch (NotFoundException e) {
			throw new RuntimeException("Error while pulling image: " + dockerImage);
		}
	}


	/**
	 * Check if a given Docker image exists locally.
	 * 
	 * @param dockerImage the docker image to run
	 * @param dockerClient the Docker client
	 */
	public static boolean dockerImageExists(String dockerImage, DockerClient dockerClient) {
		System.out.println("Check if image " + dockerImage + " exists localy");
		List<Image> images = dockerClient.listImagesCmd().exec();
		for (Image image : images) {
			for (String repoTag : image.getRepoTags()) {
				if (repoTag.equals(dockerImage)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Check if a container exists.
	 * 
	 * @param containerName the name of the container
	 * @param dockerClient the Docker client
	 * @return true if the container exists, false otherwise
	 */
	public static boolean dockerContainerExists(String containerName, DockerClient dockerClient) {
		System.out.println("Check if container " + containerName + " is already running");
		List<Container> containers = dockerClient.listContainersCmd().withShowAll(true).exec();
		for (Container container : containers) {
			if (container.getNames()[0].equals("/" + containerName)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Remove the given docker image.
	 * 
	 * @param containerName the name of the container
	 * @param dockerClient the Docker client
	 */
	public static void dockerRm(String containerName, DockerClient dockerClient) {
		// Remove container
		System.out.println("Remove the container " + containerName);
		dockerClient.removeContainerCmd(containerName).exec();
	}

	/**
	 * Stop the given container.
	 * 
	 * @param containerName the name of the container
	 * @param dockerClient the Docker client
	 */
	public static void dockerStop(String containerName, DockerClient dockerClient) {
		// Stop container
		System.out.println("Stop the container " + containerName);
		dockerClient.killContainerCmd(containerName).exec();
	}

	/**
	 * Copy file from container
	 * 
	 * @param pcapFullPath the path of the pcap file
	 * @param containerName the name of the container
	 * @param containerFile the path of the pcap file in the container
	 * @param dockerClient the Docker client
	 * @throws IOException
	 */
	public static void dockerCp(File file, String containerName, String containerFile,
			DockerClient dockerClient) throws IOException {
		System.out.println("Copy file from container");
		InputStream stream = dockerClient.copyArchiveFromContainerCmd(containerName, containerFile).exec();
		try (TarArchiveInputStream tarStream = new TarArchiveInputStream(stream)) {
			unTar(tarStream, file);
		}
	}

	/**
	 * docker Inspect IP address.
	 * 
	 * @param containerName
	 * @param dockerClient
	 * @return the ip address of the container
	 */
	public static String dockerInspectIP(String containerName, DockerClient dockerClient) {
		// Get Ip address
		System.out.println("Get IP address");
		ContainerNetwork network = dockerClient.inspectContainerCmd(containerName).exec().getNetworkSettings()
				.getNetworks().values().iterator().next();
		String ipAddress = network.getIpAddress();
		System.out.println("IP Address: " + ipAddress);
		return ipAddress;
	}

	/**
	 * Exec a command in the container.
	 * 
	 * @param command the command to execute
	 * @param containerName the name of the container
	 * @param dockerClient the Docker client
	 * @return 
	 */
	public static Adapter<Frame> dockerExec(String command, String containerName, DockerClient dockerClient) {
		System.out.println("Execute " + command + " in the container");
		String id = dockerClient.execCreateCmd(containerName)
				.withAttachStdout(true)
				.withAttachStderr(true)
				.withCmd("bash", "-c", command)
				.exec()
				.getId();
		ExecStartCmd start = dockerClient.execStartCmd(id);
		Adapter<Frame> handler = new Adapter<Frame>() {
			@Override
			public void onNext(Frame object) {
				super.onNext(object);
				System.out.println("Message from docker command: " + object);
			}

			@Override
			public void onError(Throwable throwable) {
				super.onError(throwable);
				throwable.printStackTrace();
			}
		};
		return start.exec(handler);
	}

	/**
	 * Run a docker container.
	 * 
	 * @param dockerImage the docker image to run
	 * @param containerName the name of the container
	 * @param dockerClient the Docker client
	 */
	public static void dockerRun(String dockerImage, String containerName, DockerClient dockerClient) {
		// Create container
		System.out.println("Create Docker container");
		try(CreateContainerCmd cmd = dockerClient.createContainerCmd(dockerImage)) {
			cmd.withName(containerName).withTty(true).exec();
		}

		// Start container
		System.out.println("Start Docker container");
		dockerClient.startContainerCmd(containerName).exec();
	}

	/**
	 * Untar a file.
	 * 
	 * @param tis      the tar input stream
	 * @param destFile the destination file
	 * @throws IOException
	 */
	public static void unTar(TarArchiveInputStream tis, File destFile) throws IOException {
		TarArchiveEntry tarEntry = null;
		while ((tarEntry = tis.getNextTarEntry()) != null) {
			if (tarEntry.isDirectory()) {
				if (!destFile.exists())	destFile.mkdirs();
				continue;
			}

			// It's a file
			try(FileOutputStream fos = new FileOutputStream(destFile)) {
				IOUtils.copy(tis, fos);
			}
		}
	}

	/**
	 * returns the default Docker image.
	 * 
	 * @return the default Docker image.
	 */
	public static String defaultDockerImage() {
		return "contackgen/server-attack:latest";
	}

	public static DockerClient getDockerClient() {
		DockerClientConfig config = DefaultDockerClientConfig.createDefaultConfigBuilder()
				.withDockerTlsVerify(false)
				.withRegistryUsername("dockeruser")
				.build();
		DockerHttpClient httpClient = new ApacheDockerHttpClient.Builder()
				.dockerHost(config.getDockerHost())
				.sslConfig(config.getSSLConfig())
				.maxConnections(100)
				.connectionTimeout(Duration.ofSeconds(10))
				.responseTimeout(Duration.ofSeconds(30))
				.build();
		return DockerClientImpl.getInstance(config, httpClient);
	}

	/**
	 * Parse network traffic from a pcap file.
	 * 
	 * @param pcapFile the pcap file to parse
	 */
	public static void readPcap(File pcapFile, PacketHandler callback) throws FramingException, IOException {
		System.out.println("Read pcap file: " + pcapFile + "");

		io.pkts.Pcap pcap = io.pkts.Pcap.openStream(pcapFile);
		pcap.loop(callback);
		pcap.close();
	}
}
