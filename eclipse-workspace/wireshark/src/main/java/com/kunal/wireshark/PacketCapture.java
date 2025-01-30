package com.kunal.wireshark;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import org.pcap4j.core.*;

public class PacketCapture {

    private PcapHandle handle;
    private Thread captureThread;
    private List<Packet> capturedPackets = new ArrayList<>();
    private int totalPackets = 0;
    private int tcpPacketCount = 0;
    private int udpPacketCount = 0;
    private int totalPacketSize = 0;
    private String lastPacketDetails = "No packet captured yet";
    
    private double packetRate = 0.0;
    private long lastPacketTimestamp = System.currentTimeMillis();
    private final double PACKET_RATE_THRESHOLD = 50.0; // Packets per second threshold
    private final int PACKET_THRESHOLD = 100; // Threshold for high packet count from the same IP
    private Map<String, Integer> packetCountPerIp = new HashMap<>();
   
    private JFrame frame;
    private JTextArea packetListView;
    private JTextField filterTextField;
    private JComboBox<PcapNetworkInterface> interfaceComboBox;
    private JTextArea packetDetailsView;
    private JTextArea packetStatisticsView;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new PacketCapture().createAndShowGUI());
    }
    private void createAndShowGUI() {
        frame = new JFrame("Packet Capture");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // Network interface selection panel with better layout
        JPanel interfacePanel = new JPanel(new FlowLayout(FlowLayout.LEFT)); // Use FlowLayout for horizontal alignment
        interfaceComboBox = new JComboBox<>();
        loadNetworkInterfaces();

        // Ensure the combo box is not too wide
        interfaceComboBox.setPreferredSize(new Dimension(200, 30)); 

        interfacePanel.add(new JLabel("Select Interface:"));
        interfacePanel.add(interfaceComboBox);
        
        // Filter text field panel
        filterTextField = new JTextField(20);
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filterPanel.add(new JLabel("Filter:"));
        filterPanel.add(filterTextField);

        // Packet list panel
        packetListView = new JTextArea(20, 40);
        packetListView.setEditable(false);
        packetListView.setLineWrap(true);
        packetListView.setWrapStyleWord(true);
        
        // Packet details and statistics panels
        packetDetailsView = new JTextArea(10, 40);
        packetDetailsView.setEditable(false);
        packetStatisticsView = new JTextArea(10, 40);
        packetStatisticsView.setEditable(false);

        JPanel packetDetailsPanel = new JPanel(new BorderLayout());
        packetDetailsPanel.add(new JLabel("Packet Details:"), BorderLayout.NORTH);
        packetDetailsPanel.add(new JScrollPane(packetDetailsView), BorderLayout.CENTER);
        
        JPanel packetStatisticsPanel = new JPanel(new BorderLayout());
        packetStatisticsPanel.add(new JLabel("Packet Statistics:"), BorderLayout.NORTH);
        packetStatisticsPanel.add(new JScrollPane(packetStatisticsView), BorderLayout.CENTER);
        
        // Create tabbed pane for different views
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Packet List", new JScrollPane(packetListView));
        tabbedPane.addTab("Packet Details", packetDetailsPanel);
        tabbedPane.addTab("Packet Statistics", packetStatisticsPanel);
        
        // Buttons panel
        JPanel buttonPanel = createButtonPanel();
        
        // Main layout
        frame.setLayout(new BorderLayout());
        frame.add(interfacePanel, BorderLayout.NORTH); // Add interface panel at the top
        frame.add(filterPanel, BorderLayout.CENTER);  // Filter panel in the center
        frame.add(buttonPanel, BorderLayout.SOUTH);   // Buttons at the bottom
        frame.add(tabbedPane, BorderLayout.EAST);     // Tabbed pane to the right
        
        frame.pack();  // Fit the window to the components
        frame.setVisible(true);
        
        // Add window listener for cleanup
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                stopCapture();
            }
        });
    }

   
    
    
    private void loadNetworkInterfaces() {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            for (PcapNetworkInterface nif : interfaces) {
                interfaceComboBox.addItem(nif);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(frame, "Error listing network interfaces: " + e.getMessage());
        }
    }
    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel();

        JButton startButton = new JButton("Start Capture");
        startButton.addActionListener(e -> startCapture());
        buttonPanel.add(startButton);

        JButton stopButton = new JButton("Stop Capture");
        stopButton.addActionListener(e -> stopCapture());
        buttonPanel.add(stopButton);

        JButton clearButton = new JButton("Clear Capture");
        clearButton.addActionListener(e -> clearCapture());
        buttonPanel.add(clearButton);

        JButton saveButton = new JButton("Save Capture");
        saveButton.addActionListener(e -> saveCapture());
        buttonPanel.add(saveButton);

        JButton loadButton = new JButton("Load Capture");
        loadButton.addActionListener(e -> loadCapture());
        buttonPanel.add(loadButton);

        JButton replayButton = new JButton("Replay Packets");
        replayButton.addActionListener(e -> replayPackets());
        buttonPanel.add(replayButton);

        JButton exportStatsButton = new JButton("Export Statistics");
        exportStatsButton.addActionListener(e -> exportStatistics());
        buttonPanel.add(exportStatsButton);

        JButton showSummaryButton = new JButton("Show Summary");
        showSummaryButton.addActionListener(e -> showCaptureSummary());
        buttonPanel.add(showSummaryButton);

        return buttonPanel;
    }

    private void startCapture() {
        stopCapture(); // Ensure previous capture is stopped before starting a new one

        try {
            PcapNetworkInterface nif = (PcapNetworkInterface) interfaceComboBox.getSelectedItem();
            if (nif == null) {
                packetListView.append("No interface selected.\n");
                return;
            }

            int snapLen = 65536; // Capture all packets, no truncation
            int timeoutMillis = 1000; // Timeout for capture
            handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeoutMillis);

            packetListView.append("Listening on " + nif.getName() + "...\n");

            captureThread = new Thread(() -> {
                while (handle != null && !Thread.currentThread().isInterrupted()) {
                    try {
                        Packet packet = handle.getNextPacketEx();
                        if (packet != null) {
                            capturedPackets.add(packet);
                            detectAnomalies(packet);
                            String packetInfo = getPacketInfo(packet);
                            if (filterTextField.getText().isEmpty() || packetInfo.contains(filterTextField.getText())) {
                                SwingUtilities.invokeLater(() -> {
                                    packetListView.append(packetInfo + "\n");
                                    totalPackets++;
                                    lastPacketDetails = packetInfo;
                                    if (packet.contains(TcpPacket.class)) {
                                        tcpPacketCount++;  // Increment TCP packet counter
                                    } else if (packet.contains(UdpPacket.class)) {
                                        udpPacketCount++;  // Increment UDP packet counter
                                    }
                                 
                                    updatePacketDetails();
                                   
                                    updateStatistics();
                                });
                            }
                        }
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> packetListView.append("Error capturing packets: " + e.getMessage() + "\n"));
                        break;
                    }
                }
            });

            captureThread.start();

        } catch (Exception e) {
            packetListView.append("Error: " + e.getMessage() + "\n");
        }
    }

    private void stopCapture() {
        if (handle != null) {
            handle.close();
            handle = null;
        }
        if (captureThread != null && captureThread.isAlive()) {
            captureThread.interrupt();
        }
    }

    private void clearCapture() {
        packetListView.setText("");
        capturedPackets.clear();
        totalPackets = 0;
        lastPacketDetails = "No packet captured yet";
        updatePacketDetails();
        updateStatistics();
    }

    private void saveCapture() {
        JFileChooser fileChooser = new JFileChooser();

        // Add a file filter to restrict the file type to .txt files
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Text Files", "txt");
        fileChooser.setFileFilter(filter);

        int returnValue = fileChooser.showSaveDialog(frame);
        String currentDateTime = getFormattedDateTime();
        
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();

            // Ensure the file ends with the .txt extension
            if (!file.getName().endsWith(".txt")) {
                file = new File(file.getAbsolutePath() + ".txt"); // Automatically append .txt if no extension is provided
            }

            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                // Write capturedPackets data into the text file (you may need to convert it to a string)
                writer.write("Captured Packets Data:\n");
                // Assuming capturedPackets is a list of packet objects or strings
                for (Object packet : capturedPackets) {
                    writer.write(packet.toString() + "\n"); // Convert packet to string and write
                }
                JOptionPane.showMessageDialog(frame, "Capture saved successfully.");
            } catch (IOException e) {
                JOptionPane.showMessageDialog(frame, "Error saving capture: " + e.getMessage());
            }
        }
    }

    private void loadCapture() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(frame);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
                capturedPackets = (List<Packet>) ois.readObject();
                packetListView.setText(""); // Clear existing content
                for (Packet packet : capturedPackets) {
                    packetListView.append(getPacketInfo(packet) + "\n");
                }
                JOptionPane.showMessageDialog(frame, "Capture loaded successfully.");
            } catch (IOException | ClassNotFoundException e) {
                JOptionPane.showMessageDialog(frame, "Error loading capture: " + e.getMessage());
            }
        }
    }

    private void replayPackets() {
        if (!capturedPackets.isEmpty()) {
            for (Packet packet : capturedPackets) {
                packetListView.append(getPacketInfo(packet) + " (Replayed)\n");
            }
            JOptionPane.showMessageDialog(frame, "Packets replayed successfully.");
        } else {
            JOptionPane.showMessageDialog(frame, "No packets to replay.");
        }
    }
    private void detectAnomalies(Packet packet) {
    	IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet != null) {
            // Anomaly detection based on source IP address
            String srcIP = ipV4Packet.getHeader().getSrcAddr().toString();
            packetCountPerIp.put(srcIP, packetCountPerIp.getOrDefault(srcIP, 0) + 1);
            
            if (packetCountPerIp.get(srcIP) > PACKET_THRESHOLD) {
                // If the same IP sends more than a certain threshold of packets, flag it
                packetListView.append("Anomalous traffic detected from IP: " + srcIP + "\n");
            }
        }

        // Anomaly detection based on packet rate (packets per second)
        long currentTimestamp = System.currentTimeMillis();
        double timeDifference = (currentTimestamp - lastPacketTimestamp) / 1000.0; // Time in seconds
        packetRate = 1.0 / timeDifference; // Simple packet rate (packets per second)

        if (packetRate > PACKET_RATE_THRESHOLD) {
            // If the packet rate exceeds the threshold, flag it as anomalous
            packetListView.append("Anomalous high packet rate detected: " + packetRate + " packets/sec\n");
        }

        lastPacketTimestamp = currentTimestamp;

        // Check for unusual packet sizes
        if (packet.length() > 15000) {
            // Flag if packet size is unusually large (this is just an example threshold)
            packetListView.append("Anomalous packet size detected: " + packet.length() + " bytes\n");
        }

        // Additional protocol-based anomaly checks can be added here
        // For example: check if the packet contains unusual protocols or ports
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            int destPort = tcpPacket.getHeader().getDstPort().value();
            if (destPort == 5155) {  // Example of a suspicious port (can be customized)
                packetListView.append("Anomalous traffic detected on suspicious port: " + destPort + "\n");
            }
        }
    }

    private void exportStatistics() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showSaveDialog(frame);
        String currentDateTime =getFormattedDateTime();
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (PrintWriter writer = new PrintWriter(new FileWriter(file))) {
            	writer.println("Date And Time " + currentDateTime ); 
            	writer.println("Total Packets: " + totalPackets);
                writer.println("TCP Packets: " + tcpPacketCount);
                writer.println("UDP Packets: " + udpPacketCount);
                writer.println("Total Packet Size: " + totalPacketSize + " bytes");
                JOptionPane.showMessageDialog(frame, "Statistics exported successfully.");
            } catch (FileNotFoundException e) {
                JOptionPane.showMessageDialog(frame, "Error exporting statistics: " + e.getMessage());
            } catch (IOException e) {
                JOptionPane.showMessageDialog(frame, "Error writing to file: " + e.getMessage());
            }
        }
    }

    private void showCaptureSummary() {
        JOptionPane.showMessageDialog(frame, "Total Packets: " + totalPackets +
                "\nTCP Packets: " + tcpPacketCount +
                "\nUDP Packets: " + udpPacketCount +
                "\nTotal Packet Size: " + totalPacketSize + " bytes" +
                "\nLast Packet: " + lastPacketDetails);
    }

    private void updatePacketDetails() {
        packetDetailsView.setText(lastPacketDetails);
        
    }

    private void updateStatistics() {
    	
        packetStatisticsView.setText("Total Packets: " + totalPackets +
                "\nTCP Packets: " + tcpPacketCount +
                "\nUDP Packets: " + udpPacketCount +
                "\nTotal Packet Size: " + totalPacketSize + " bytes");
    }
    private void updatePacketStatistics(Packet packet) {
        totalPackets++;
        totalPacketSize += packet.length();

        if (packet.contains(TcpPacket.class)) {
            tcpPacketCount++;
        } else if (packet.contains(UdpPacket.class)) {
            udpPacketCount++;
        }
    }


    
        public String getFormattedDateTime() {
            // Get current date and time
            LocalDateTime now = LocalDateTime.now();

            // Format the date and time to a suitable string format for filenames
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
            return now.format(formatter);
        }
    

    
    private String getPacketInfo(Packet packet) {
        StringBuilder sb = new StringBuilder();
        sb.append("+----------------------+-----------------------------------+\n");
        sb.append("|        Field        |              Value                |\n");
        sb.append("+----------------------+-----------------------------------+\n");

        // Check for IPv4 packet
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            IpV4Packet.IpV4Header header = ipV4Packet.getHeader();
            
            sb.append("| Protocol            | IPv4                               |\n");
            sb.append("| Version             | ").append(header.getVersion().value()).append("\n");
            sb.append("| Header Length       | ").append(header.getIhlAsInt()).append(" bytes\n");
            sb.append("| Service Type        | ").append(header.getTos().toString()).append("\n");
            sb.append("| Total Length        | ").append(header.getTotalLengthAsInt()).append(" bytes\n");
            sb.append("| Identification      | ").append(header.getIdentificationAsInt()).append("\n");
           
            sb.append("| Fragment Offset     | ").append(header.getFragmentOffset()).append("\n");
            sb.append("| TTL                 | ").append(header.getTtl()).append("\n");
            sb.append("| Protocol Type       | ").append(header.getProtocol()).append("\n");
            sb.append("| Header Checksum     | ").append(header.getHeaderChecksum()).append("\n");
            sb.append("| Source IP           | ").append(header.getSrcAddr()).append("\n");
            sb.append("| Destination IP      | ").append(header.getDstAddr()).append("\n");

            // Check if it's a TCP packet within IPv4
            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                sb.append("| Transport Protocol  | TCP                               |\n");
                sb.append("| Source Port         | ").append(tcpHeader.getSrcPort()).append("\n");
                sb.append("| Destination Port    | ").append(tcpHeader.getDstPort()).append("\n");
                sb.append("| Sequence Number     | ").append(tcpHeader.getSequenceNumber()).append("\n");
                sb.append("| Acknowledgment Num  | ").append(tcpHeader.getAcknowledgmentNumber()).append("\n");
                sb.append("| Flags               | ").append(tcpHeader.getFin()).append("\n");
                sb.append("| Window Size         | ").append(tcpHeader.getWindow()).append("\n");
                sb.append("| Checksum            | ").append(tcpHeader.getChecksum()).append("\n");
                sb.append("| Urgent Pointer      | ").append(tcpHeader.getUrgentPointer()).append("\n");
            } else if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                sb.append("| Transport Protocol  | UDP                               |\n");
                sb.append("| Source Port         | ").append(udpHeader.getSrcPort()).append("\n");
                sb.append("| Destination Port    | ").append(udpHeader.getDstPort()).append("\n");
                sb.append("| Length              | ").append(udpHeader.getLength()).append(" bytes\n");
                sb.append("| Checksum            | ").append(udpHeader.getChecksum()).append("\n");
            }
        }

        // Check for IPv6 packet
        else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
            IpV6Packet.IpV6Header header = ipV6Packet.getHeader();
            
            sb.append("| Protocol            | IPv6                               |\n");
            sb.append("| Version             | ").append(header.getVersion().value()).append("\n");
            sb.append("| Traffic Class       | ").append(header.getTrafficClass()).append("\n");
            sb.append("| Flow Label          | ").append(header.getFlowLabel()).append("\n");
            sb.append("| Payload Length      | ").append(header.getPayloadLengthAsInt()).append(" bytes\n");
            sb.append("| Next Header         | ").append(header.getNextHeader()).append("\n");
            sb.append("| Hop Limit           | ").append(header.getHopLimit()).append("\n");
            sb.append("| Source IP           | ").append(header.getSrcAddr()).append("\n");
            sb.append("| Destination IP      | ").append(header.getDstAddr()).append("\n");

            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                sb.append("| Transport Protocol  | TCP                               |\n");
                sb.append("| Source Port         | ").append(tcpHeader.getSrcPort()).append("\n");
                sb.append("| Destination Port    | ").append(tcpHeader.getDstPort()).append("\n");
                sb.append("| Sequence Number     | ").append(tcpHeader.getSequenceNumber()).append("\n");
                sb.append("| Acknowledgment Num  | ").append(tcpHeader.getAcknowledgmentNumber()).append("\n");
                sb.append("| Flags               | ").append(tcpHeader.getFin()).append("\n");
                sb.append("| Window Size         | ").append(tcpHeader.getWindow()).append("\n");
                sb.append("| Checksum            | ").append(tcpHeader.getChecksum()).append("\n");
                sb.append("| Urgent Pointer      | ").append(tcpHeader.getUrgentPointer()).append("\n");
            } else if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                sb.append("| Transport Protocol  | UDP                               |\n");
                sb.append("| Source Port         | ").append(udpHeader.getSrcPort()).append("\n");
                sb.append("| Destination Port    | ").append(udpHeader.getDstPort()).append("\n");
                sb.append("| Length              | ").append(udpHeader.getLength()).append(" bytes\n");
                sb.append("| Checksum            | ").append(udpHeader.getChecksum()).append("\n");
            }
        } else {
            sb.append("| Protocol            | Unknown                            |\n");
        }

        sb.append("+----------------------+-----------------------------------+\n");
        return sb.toString();
    } 

  
		

    private String getPacketType(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            return "IPv4";
        } else if (packet.contains(IpV6Packet.class)) {
            return "IPv6";
        }
        return "Unknown";
    }
   
}
