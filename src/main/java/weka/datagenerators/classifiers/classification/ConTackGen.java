package weka.datagenerators.classifiers.classification;

import static fr.contacgen.ConTacGenUtils.defaultDockerImage;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;
import java.util.function.Consumer;

import fr.contacgen.ConTacGenPacketHandler;
import fr.contacgen.DockerRunner;
import fr.contacgen.MITMAttack;
import fr.contacgen.PacketData;
import fr.contacgen.UDPDos;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.Option;
import weka.core.Tag;
import weka.core.SelectedTag;
import weka.core.Utils;
import weka.datagenerators.ClassificationGenerator;

@SuppressWarnings("serial")
public class ConTackGen extends ClassificationGenerator {
    public static final String DATE_STRING = "yyyy-MM-dd HH:mm:ss";

    public static final int ATTACK_UDPDOS = 0;
    public static final int ATTACK_MITM = 1;
    public static final Tag[] TAGS_ATTACK = {
        new Tag(ATTACK_UDPDOS, "UDPDos"),
        new Tag(ATTACK_MITM, "MITM")
    };

    private static final Attribute[] DATASET_ATTRIBUTES = new Attribute[] {
            new Attribute("srcIP", true),
            new Attribute("dstIP", true),
            new Attribute("type", true),
            new Attribute("headerChecksum", true),
            new Attribute("attack"),
            new Attribute("protocol"),
            new Attribute("version"),
            new Attribute("IHL"),
            new Attribute("length"),
            new Attribute("identification"),
            new Attribute("fragmentOffset"),
            new Attribute("TTL"),
            new Attribute("timer"),
            new Attribute("timestamp", DATE_STRING),
            new Attribute("content", true)
    };

    private String dockerImage = defaultDockerImage();
    protected int duration = defaultDuration();
    protected int m_AttackType = ATTACK_UDPDOS; 

    public String globalInfo() {
        return "Generates a contextual data set of network traffic.\n"
             + "Use the AttackType property to choose between UDPDos and MITM.\n"
             + "You can also set the duration of the capture.";
    }

    public void setAttackType(SelectedTag newType) {
        if (newType.getTags() == TAGS_ATTACK) {
            m_AttackType = newType.getSelectedTag().getID();
        }
    }

    public SelectedTag getAttackType() {
        return new SelectedTag(m_AttackType, TAGS_ATTACK);
    }

    public String attackTypeTipText() {
        return "Choose the type of attack to generate (UDPDos or MITM).";
    }

    public int getDuration_s() {
        return duration;
    }

    public void setDuration_s(int duration) {
        this.duration = duration;
    }

    public String duration_sTipText() {
        return "Duration of the network capture and attack simulation in seconds.";
    }

    @Override
    public Enumeration<Option> listOptions() {
        Vector<Option> newVector = enumToVector(super.listOptions());
        newVector.add(new Option("\tThe network traffic capture duration in seconds (default: 60)",
                                 "duration_s", 1, "-duration_s <int>"));
        newVector.add(new Option("\tThe type of attack: UDPDos or MITM (default: UDPDos)",
                                 "attack_type", 1, "-attack_type <UDPDos|MITM>"));
        return newVector.elements();
    }

    @Override
    public void setOptions(String[] options) throws Exception {
        super.setOptions(options);

        String durationOpt = Utils.getOption("duration_s", options);
        if(!durationOpt.isEmpty()) {
            this.duration = Integer.parseInt(durationOpt);
        }

        String atype = Utils.getOption("attack_type", options);
        if(!atype.isEmpty()) {
            if (atype.equalsIgnoreCase("UDPDos")) {
                m_AttackType = ATTACK_UDPDOS;
            } else if (atype.equalsIgnoreCase("MITM")) {
                m_AttackType = ATTACK_MITM;
            } else {
                throw new IllegalArgumentException("Unknown attack type: " + atype);
            }
        }
    }

    @Override
    public String[] getOptions() {
        List<String> result = new ArrayList<>();
        for (String opt : super.getOptions()) {
            result.add(opt);
        }

        result.add("-duration_s");
        result.add(String.valueOf(duration));

        result.add("-attack_type");
        if(m_AttackType == ATTACK_UDPDOS) {
            result.add("UDPDos");
        } else {
            result.add("MITM");
        }

        return result.toArray(new String[0]);
    }

    @Override
    public Instances defineDataFormat() throws Exception {
        ArrayList<Attribute> atts = new ArrayList<>(Arrays.asList(DATASET_ATTRIBUTES));
        m_DatasetFormat = new Instances(getRelationNameToUse(), atts, 0);
        return super.defineDataFormat();
    }

    @Override
    public Instance generateExample() throws Exception {
        return null;
    }

    public void handlePacket(PacketData packet, Instances inst) {
        if (inst.size() >= this.getNumExamples()) return;

        Instance instance = new DenseInstance(inst.numAttributes());
        instance.setDataset(getDatasetFormat());

        for (int i = 0; i < inst.numAttributes(); i++) {
            final Attribute entry = inst.attribute(i);
            String value = null;
            double numVal = 0;
            switch(entry.name()) {
                case "srcIP": value = packet.getSrcIP(); break;
                case "dstIP": value = packet.getDstIP(); break;
                case "type": value = packet.getType(); break;
                case "headerChecksum": value = packet.getChecksum(); break;
                case "protocol": numVal = packet.getProtocol(); break;
                case "version": numVal = packet.getVersion(); break;
                case "IHL": numVal = packet.getHeaderLength(); break;
                case "length": numVal = packet.getTotalLength(); break;
                case "identification": numVal = packet.getId(); break;
                case "fragmentOffset": numVal = packet.getFragmentOffset(); break;
                case "TTL": numVal = packet.getTTL(); break;
                case "attack": numVal = packet.isAttack() ? 1 : 0; break;
                case "content": value = packet.getContentHex(); break;
                case "timer": numVal = packet.getTimer() / 1000.; break;
                case "timestamp": numVal = packet.getTimestamp() / 1000.; break;
                default:
                    throw new IllegalArgumentException("Error setting attribute '" + entry.name() + "' is unrecognized.");
            }
            if(value != null)
                instance.setValue(entry, value);
            else
                instance.setValue(entry, numVal);
        }

        inst.add(instance);
    }

    @Override
    public Instances generateExamples() throws IllegalStateException, InterruptedException, IOException {
        System.out.println("Generating data set...");
        if (this.m_DatasetFormat == null) throw new IllegalStateException("Dataset format not defined.");

        ConTacGenPacketHandler handler = ConTacGenPacketHandler.getInstance();
        handler.clear();

        Consumer<InetAddress> attackRunnable;
        if(m_AttackType == ATTACK_UDPDOS) {
            attackRunnable = (InetAddress t) -> new UDPDos(t, m_Seed).run();
        } else {
            attackRunnable = (InetAddress t) -> {
                MITMAttack mitm = new MITMAttack(t.getHostAddress(), 8080, 9090, duration);
                mitm.run();
            };
        }


        DockerRunner.dockerMain(dockerImage, attackRunnable, this.duration);

        Instances result = new Instances(this.m_DatasetFormat, 0);
        handler.foreach((PacketData packet) -> handlePacket(packet, result)).clear();

        return result;
    }

    @Override
    public String generateStart() throws Exception {
        return "ConTackGen data";
    }

    @Override
    public String generateFinished() throws Exception {
        return "";
    }

    @Override
    public boolean getSingleModeFlag() throws Exception {
        return false;
    }

    @Override
    public String getRevision() {
        return "00003";
    }

    protected int defaultDuration() {
        return 60;
    }

    public static void main(String[] args) {
        runDataGenerator(new ConTackGen(), args);
    }
}
