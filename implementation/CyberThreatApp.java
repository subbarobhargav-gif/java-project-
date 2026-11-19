import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.plaf.FontUIResource;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public class CyberThreatApp extends JFrame {
    private static final long serialVersionUID = 1L;

    private List<Threat> threatList = new ArrayList<>();
    private DefaultTableModel tableModel;
    private JTable threatTable;
    private JTextArea explanationArea;
    private XAIVisualPanel visualPanel;
    private GraphDashboardPanel graphPanel;
    private TableRowSorter<DefaultTableModel> tableSorter;
    private JCheckBox simulateMitigationCheck;
    private JLabel visibleCountLabel;
    private JLabel totalCountValue;
    private JLabel criticalCountValue;
    private JLabel highCountValue;
    private JLabel averageRiskValue;

    // Input fields
    private JTextField idField, nameField, cvssField;
    private JTextField searchField;
    private JComboBox<String> categoryBox, criticalityBox;
    private JComboBox<String> priorityFilterBox, categoryFilterBox;
    private JCheckBox exploitCheck, internetCheck;
    private final RiskScoringConfig scoringConfig = new RiskScoringConfig();
    private final Path appDataDirectory = Paths.get(System.getProperty("user.home"), ".cyber-threat-app");
    private final Path findingsFile = appDataDirectory.resolve("findings.csv");
    private final Path settingsFile = appDataDirectory.resolve("risk-model.properties");

    public CyberThreatApp() {
        setTitle("Cyber Threat Risk Prioritization Dashboard");
        setSize(1150, 720);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));

        // Top Banner
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(15, 23, 42));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        JLabel titleLabel = new JLabel("Cyber Threat Risk Dashboard");
        titleLabel.setForeground(Color.WHITE);
        titleLabel.setFont(new Font("Avenir Next", Font.BOLD, 20));
        JLabel subLabel = new JLabel("Weighted decision-support score  |  Not a verified prediction or live alert");
        subLabel.setForeground(new Color(148, 163, 184));
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(subLabel, BorderLayout.SOUTH);

        JLabel clockLabel = new JLabel();
        clockLabel.setForeground(new Color(203, 213, 225));
        clockLabel.setFont(new Font("Avenir Next", Font.BOLD, 14));
        clockLabel.setHorizontalAlignment(SwingConstants.RIGHT);
        headerPanel.add(clockLabel, BorderLayout.EAST);

        DateTimeFormatter clockFormatter = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy  |  HH:mm:ss");
        Runnable updateClock = () -> clockLabel.setText(
            LocalDateTime.now().format(clockFormatter));
        updateClock.run();
        new Timer(1000, event -> updateClock.run()).start();

        JPanel banner = new JPanel(new BorderLayout());
        banner.setOpaque(false);
        banner.add(headerPanel, BorderLayout.CENTER);
        banner.add(new HeaderIllustration(), BorderLayout.EAST);
        add(banner, BorderLayout.NORTH);

        // Left Panel: Add New Threat Form
        JPanel formPanel = new JPanel(new GridLayout(0, 1, 6, 6));
        formPanel.setPreferredSize(new Dimension(290, 0));
        formPanel.setBorder(BorderFactory.createTitledBorder("Ingest Cyber Threat / CVE"));
        formPanel.setBackground(new Color(248, 250, 252));

        idField = new JTextField("CVE-2026-1042");
        nameField = new JTextField("OpenSSL Buffer Overflow");
        categoryBox = new JComboBox<>(new String[]{
            "Remote Code Execution", 
            "Privilege Escalation", 
            "SQL Injection", 
            "DDoS / Network", 
            "Phishing / Malware"
        });
        idField.setToolTipText("Unique identifier for this finding; duplicate IDs are not allowed.");
        nameField.setToolTipText("Short, recognizable name for the vulnerability.");
        categoryBox.setToolTipText("Broad attack or vulnerability category.");
        cvssField = new JTextField("8.8");
        cvssField.setToolTipText("CVSS base score from 0.0 to 10.0; this is one input to the local risk model.");
        criticalityBox = new JComboBox<>(new String[]{
            "1 - Low (Test Server)", 
            "2 - Moderate", 
            "3 - Important", 
            "4 - High (App Server)", 
            "5 - Mission Critical (DB/Auth)"
        });
        criticalityBox.setSelectedIndex(4);
        criticalityBox.setToolTipText("Operational importance of the affected asset, from 1 (low) to 5 (mission critical).");
        exploitCheck = new JCheckBox("Active Exploit Available in Wild", true);
        exploitCheck.setToolTipText("Select if there is an active exploit available in the wild.");
        internetCheck = new JCheckBox("Internet-Facing / External Asset", true);
        internetCheck.setToolTipText("Select if the affected asset is reachable from the internet.");

        JButton addButton = new JButton("Analyze & Prioritize Threat");
        addButton.setBackground(new Color(37, 99, 235));
        addButton.setForeground(Color.WHITE);
        addButton.setOpaque(true);
        addButton.setBorderPainted(false);
        addButton.setFocusPainted(false);
        addButton.setFont(addButton.getFont().deriveFont(Font.BOLD));

        JButton exportButton = new JButton("Export Prioritized Report (.txt)");
        exportButton.setBackground(new Color(226, 232, 240));
        exportButton.setForeground(new Color(30, 41, 59));
        exportButton.setFocusPainted(false);
        JButton importCsvButton = new JButton("Import CSV");
        JButton exportCsvButton = new JButton("Export CSV");
        JButton settingsButton = new JButton("Scoring Settings");
        JButton remediationButton = new JButton("Update Remediation");
        JButton deleteButton = new JButton("Delete Selected");
        JButton clearAllButton = new JButton("Clear All");

        formPanel.add(new JLabel("Threat / CVE ID:"));
        formPanel.add(idField);
        formPanel.add(new JLabel("Vulnerability Name:"));
        formPanel.add(nameField);
        formPanel.add(new JLabel("Attack Category:"));
        formPanel.add(categoryBox);
        formPanel.add(new JLabel("CVSS Base Score (0.0 - 10.0):"));
        formPanel.add(cvssField);
        formPanel.add(new JLabel("Target Asset Criticality:"));
        formPanel.add(criticalityBox);
        formPanel.add(exploitCheck);
        formPanel.add(internetCheck);
        formPanel.add(addButton);
        formPanel.add(exportButton);
        JPanel dataActionPanel = new JPanel(new GridLayout(1, 2, 6, 6));
        dataActionPanel.setOpaque(false);
        dataActionPanel.add(importCsvButton);
        dataActionPanel.add(exportCsvButton);
        formPanel.add(dataActionPanel);
        formPanel.add(settingsButton);
        JPanel findingActionPanel = new JPanel(new GridLayout(1, 2, 6, 6));
        findingActionPanel.setOpaque(false);
        findingActionPanel.add(remediationButton);
        findingActionPanel.add(deleteButton);
        formPanel.add(findingActionPanel);
        formPanel.add(clearAllButton);

        add(formPanel, BorderLayout.WEST);

        // Center & Bottom Split: Threat Table + XAI Explanation Panel
        String[] columns = {"Rank", "Threat ID", "Vulnerability Name", "Category", "CVSS", "Risk Score", "Priority", "Status"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        threatTable = new JTable(tableModel);
        threatTable.setRowHeight(32);
        threatTable.setFont(new Font("Avenir Next", Font.PLAIN, 13));
        threatTable.setForeground(new Color(30, 41, 59));
        threatTable.setBackground(Color.WHITE);
        threatTable.setGridColor(new Color(226, 232, 240));
        threatTable.setSelectionBackground(new Color(219, 234, 254));
        threatTable.setSelectionForeground(new Color(30, 41, 59));
        threatTable.setShowVerticalLines(false);
        threatTable.setIntercellSpacing(new Dimension(0, 1));
        threatTable.getTableHeader().setBackground(new Color(226, 232, 240));
        threatTable.getTableHeader().setForeground(new Color(30, 41, 59));
        threatTable.getTableHeader().setFont(new Font("Avenir Next", Font.BOLD, 12));
        tableSorter = new TableRowSorter<>(tableModel);
        threatTable.setRowSorter(tableSorter);
        threatTable.getSelectionModel().addListSelectionListener(e -> {
            int row = threatTable.getSelectedRow();
            if (!e.getValueIsAdjusting() && row >= 0) {
                int modelRow = threatTable.convertRowIndexToModel(row);
                if (modelRow < 0 || modelRow >= threatList.size()) return;
                updateSelectedThreatView();
            } else if (!e.getValueIsAdjusting()) {
                explanationArea.setText("");
                visualPanel.setThreat(null, null);
            }
        });

        // Color code Priority column
        threatTable.getColumnModel().getColumn(6).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                String status = value.toString();
                setFont(getFont().deriveFont(Font.BOLD));
                if (!isSelected) {
                    if ("CRITICAL".equals(status)) { 
                        c.setBackground(new Color(254, 226, 226)); 
                        c.setForeground(new Color(185, 28, 28)); 
                    } else if ("HIGH".equals(status)) { 
                        c.setBackground(new Color(255, 237, 213)); 
                        c.setForeground(new Color(194, 65, 12)); 
                    } else if ("MEDIUM".equals(status)) { 
                        c.setBackground(new Color(254, 249, 195)); 
                        c.setForeground(new Color(161, 98, 7)); 
                    } else { 
                        c.setBackground(new Color(220, 252, 231)); 
                        c.setForeground(new Color(21, 128, 61)); 
                    }
                }
                return c;
            }
        });
        threatTable.getColumnModel().getColumn(7).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                            boolean hasFocus, int row, int col) {
                Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (!isSelected) {
                    if ("Resolved".equals(value)) {
                        component.setBackground(new Color(220, 252, 231));
                        component.setForeground(new Color(21, 128, 61));
                    } else if ("In Progress".equals(value)) {
                        component.setBackground(new Color(219, 234, 254));
                        component.setForeground(new Color(29, 78, 216));
                    } else {
                        component.setBackground(new Color(254, 249, 195));
                        component.setForeground(new Color(161, 98, 7));
                    }
                }
                return component;
            }
        });

        JScrollPane tableScroll = new JScrollPane(threatTable);
        JPanel filterPanel = new JPanel(new BorderLayout(8, 0));
        filterPanel.setOpaque(false);
        searchField = new JTextField();
        searchField.setToolTipText("Search by ID, name, category, or remediation status");
        searchField.putClientProperty("JTextField.placeholderText", "Search findings...");
        priorityFilterBox = new JComboBox<>(new String[]{"All Priorities", "CRITICAL", "HIGH", "MEDIUM", "LOW"});
        String[] categoryFilters = new String[categoryBox.getItemCount() + 1];
        categoryFilters[0] = "All Categories";
        for (int i = 0; i < categoryBox.getItemCount(); i++) {
            categoryFilters[i + 1] = categoryBox.getItemAt(i);
        }
        categoryFilterBox = new JComboBox<>(categoryFilters);
        visibleCountLabel = new JLabel("Showing 0 of 0 findings");
        JPanel filterControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        filterControls.setOpaque(false);
        filterControls.add(priorityFilterBox);
        filterControls.add(categoryFilterBox);
        filterControls.add(visibleCountLabel);
        filterPanel.add(searchField, BorderLayout.CENTER);
        filterPanel.add(filterControls, BorderLayout.EAST);
        JPanel queuePanel = new JPanel(new BorderLayout(0, 8));
        queuePanel.setBorder(BorderFactory.createTitledBorder("Prioritized Vulnerability Queue"));
        queuePanel.add(filterPanel, BorderLayout.NORTH);
        queuePanel.add(tableScroll, BorderLayout.CENTER);

        // Bottom XAI Details Panel
        JPanel xaiBottomPanel = new JPanel(new GridLayout(1, 2, 10, 10));
        xaiBottomPanel.setPreferredSize(new Dimension(0, 240));

        explanationArea = new JTextArea();
        explanationArea.setEditable(false);
        explanationArea.setFont(new Font("Avenir Next", Font.PLAIN, 13));
        explanationArea.setBackground(new Color(248, 250, 252));
        explanationArea.setForeground(new Color(30, 41, 59));
        explanationArea.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        JScrollPane textScroll = new JScrollPane(explanationArea);
        textScroll.setBorder(BorderFactory.createEmptyBorder());
        simulateMitigationCheck = new JCheckBox(
            "Simulate Mitigation (Block External Exposure & Apply Virtual Patch)");
        simulateMitigationCheck.setToolTipText(
            "Preview risk after forcing internal-only exposure and halving exploit impact. Preview is not saved.");
        JPanel assessmentPanel = new JPanel(new BorderLayout(0, 4));
        assessmentPanel.setBorder(BorderFactory.createTitledBorder("Risk Assessment & Recommended Response"));
        assessmentPanel.add(simulateMitigationCheck, BorderLayout.NORTH);
        assessmentPanel.add(textScroll, BorderLayout.CENTER);

        visualPanel = new XAIVisualPanel();

        xaiBottomPanel.add(assessmentPanel);
        xaiBottomPanel.add(visualPanel);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, queuePanel, xaiBottomPanel);
        centerSplit.setResizeWeight(0.55);
        graphPanel = new GraphDashboardPanel();

        JTabbedPane analysisTabs = new JTabbedPane();
        analysisTabs.addTab("Prioritization Dashboard", centerSplit);
        analysisTabs.addTab("Graphical Analysis", graphPanel);

        JPanel summaryPanel = new JPanel(new GridLayout(1, 4, 10, 0));
        summaryPanel.setOpaque(false);
        totalCountValue = new JLabel("0");
        criticalCountValue = new JLabel("0");
        highCountValue = new JLabel("0");
        averageRiskValue = new JLabel("0.0");
        summaryPanel.add(createMetricCard("Tracked findings", totalCountValue,
            "Saved vulnerability findings", new Color(37, 99, 235)));
        summaryPanel.add(createMetricCard("Critical priority", criticalCountValue,
            "Immediate review recommended", new Color(220, 38, 38)));
        summaryPanel.add(createMetricCard("High priority", highCountValue,
            "Urgent remediation queue", new Color(234, 88, 12)));
        summaryPanel.add(createMetricCard("Average risk", averageRiskValue,
            "Out of 100 points", new Color(13, 148, 136)));

        JPanel dashboardPanel = new JPanel(new BorderLayout(0, 10));
        dashboardPanel.setOpaque(false);
        dashboardPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        dashboardPanel.add(summaryPanel, BorderLayout.NORTH);
        dashboardPanel.add(analysisTabs, BorderLayout.CENTER);
        add(dashboardPanel, BorderLayout.CENTER);

        // Button Actions
        addButton.addActionListener(e -> addThreatFromForm());
        exportButton.addActionListener(e -> exportReport());
        importCsvButton.addActionListener(e -> importCsv());
        exportCsvButton.addActionListener(e -> exportCsv());
        settingsButton.addActionListener(e -> showScoringSettings());
        remediationButton.addActionListener(e -> editSelectedRemediation());
        deleteButton.addActionListener(e -> deleteSelectedThreat());
        clearAllButton.addActionListener(e -> clearAllFindings());
        simulateMitigationCheck.addActionListener(e -> updateSelectedThreatView());
        priorityFilterBox.addActionListener(e -> updateTableFilter());
        categoryFilterBox.addActionListener(e -> updateTableFilter());
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { updateTableFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { updateTableFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { updateTableFilter(); }
        });

        loadPersistedState();
        if (threatList.isEmpty() && !Files.exists(findingsFile)) {
            loadSampleData();
        }
    }

    private void loadSampleData() {
        threatList.add(new Threat("CVE-2026-0192", "Apache Struts RCE", "Remote Code Execution", 9.8, 5, true, true, scoringConfig));
        threatList.add(new Threat("CVE-2026-0441", "PostgreSQL Auth Bypass", "Privilege Escalation", 8.1, 5, false, false, scoringConfig));
        threatList.add(new Threat("CVE-2026-0812", "Internal Printer SMB Leak", "DDoS / Network", 5.3, 1, false, false, scoringConfig));
        threatList.add(new Threat("CVE-2026-0915", "Web Portal Reflected XSS", "SQL Injection", 6.5, 3, true, true, scoringConfig));
        refreshTable();
        persistApplicationState();
    }

    private void addThreatFromForm() {
        try {
            String id = idField.getText().trim();
            String name = nameField.getText().trim();
            String cat = (String) categoryBox.getSelectedItem();
            if (id.isEmpty() || name.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Threat ID and vulnerability name are required.",
                    "Missing Information", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (threatList.stream().anyMatch(t -> t.getId().equalsIgnoreCase(id))) {
                JOptionPane.showMessageDialog(this, "A finding with this ID already exists.",
                    "Duplicate Finding", JOptionPane.ERROR_MESSAGE);
                return;
            }
            double cvss = Double.parseDouble(cvssField.getText().trim());
            if (!Double.isFinite(cvss) || cvss < 0 || cvss > 10) throw new NumberFormatException();
            int crit = criticalityBox.getSelectedIndex() + 1;
            boolean exploit = exploitCheck.isSelected();
            boolean internet = internetCheck.isSelected();

            threatList.add(new Threat(id, name, cat, cvss, crit, exploit, internet, scoringConfig));
            refreshTable();
            persistApplicationState();
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Please enter a valid CVSS score between 0.0 and 10.0.", "Input Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void refreshTable() {
        threatList.sort(Comparator.comparingDouble(Threat::getFinalRiskScore).reversed());
        tableModel.setRowCount(0);
        int rank = 1;
        for (Threat t : threatList) {
            tableModel.addRow(new Object[]{
                "#" + rank++,
                t.getId(),
                t.getName(),
                t.getCategory(),
                t.getCvssScore(),
                String.format(Locale.ROOT, "%.1f / 100", t.getFinalRiskScore()),
                t.getPriorityLevel(),
                t.status
            });
        }
        if (graphPanel != null) {
            graphPanel.updateGraphs(threatList);
        }
        updateSummaryCards();
        updateVisibleCount();
        if (threatTable.getRowCount() > 0) {
            threatTable.setRowSelectionInterval(0, 0);
        }
    }

    private void updateTableFilter() {
        if (tableSorter == null) return;
        String query = searchField.getText().trim().toLowerCase(Locale.ROOT);
        String priority = (String) priorityFilterBox.getSelectedItem();
        String category = (String) categoryFilterBox.getSelectedItem();
        tableSorter.setRowFilter(new javax.swing.RowFilter<DefaultTableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                boolean matchesQuery = query.isEmpty();
                for (int column = 0; !matchesQuery && column < entry.getValueCount(); column++) {
                    Object value = entry.getValue(column);
                    matchesQuery = value != null && value.toString().toLowerCase(Locale.ROOT).contains(query);
                }
                boolean matchesPriority = "All Priorities".equals(priority)
                    || priority.equals(entry.getStringValue(6));
                boolean matchesCategory = "All Categories".equals(category)
                    || category.equals(entry.getStringValue(3));
                return matchesQuery && matchesPriority && matchesCategory;
            }
        });
        updateVisibleCount();
    }

    private void updateVisibleCount() {
        if (visibleCountLabel != null && threatTable != null) {
            visibleCountLabel.setText("Showing " + threatTable.getRowCount()
                + " of " + threatList.size() + " findings");
        }
    }

    private void editSelectedRemediation() {
        int viewRow = threatTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Select a finding before updating its remediation details.",
                "No Finding Selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Threat threat = threatList.get(threatTable.convertRowIndexToModel(viewRow));
        JComboBox<String> statusBox = new JComboBox<>(new String[]{"Open", "In Progress", "Resolved"});
        statusBox.setSelectedItem(threat.status);
        JTextField ownerField = new JTextField(threat.owner);
        JTextField dueDateField = new JTextField(threat.dueDate);
        JTextArea notesArea = new JTextArea(threat.notes, 5, 28);
        notesArea.setLineWrap(true);
        notesArea.setWrapStyleWord(true);
        JCheckBox applySimulationCheck = new JCheckBox("Commit simulated mitigation to this finding");
        applySimulationCheck.setSelected(simulateMitigationCheck.isSelected());
        applySimulationCheck.setToolTipText("Sets exposure to internal-only and reduces exploit impact to 50%.");

        JPanel fields = new JPanel(new GridLayout(0, 2, 8, 8));
        fields.add(new JLabel("Status"));
        fields.add(statusBox);
        fields.add(new JLabel("Owner"));
        fields.add(ownerField);
        fields.add(new JLabel("Due date (YYYY-MM-DD)"));
        fields.add(dueDateField);
        fields.add(new JLabel("Notes"));
        fields.add(new JScrollPane(notesArea));
        if (simulateMitigationCheck.isSelected()) {
            fields.add(new JLabel("Risk model"));
            fields.add(applySimulationCheck);
        }

        int result = JOptionPane.showConfirmDialog(this, fields,
            "Remediation — " + threat.getId(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;
        String dueDate = dueDateField.getText().trim();
        try {
            if (!dueDate.isEmpty()) LocalDate.parse(dueDate);
        } catch (DateTimeParseException ex) {
            JOptionPane.showMessageDialog(this, "Enter a valid due date in YYYY-MM-DD format, or leave it blank.",
                "Invalid Due Date", JOptionPane.ERROR_MESSAGE);
            return;
        }
        threat.status = (String) statusBox.getSelectedItem();
        threat.owner = ownerField.getText().trim();
        threat.dueDate = dueDate;
        threat.notes = notesArea.getText().trim();
        if (simulateMitigationCheck.isSelected() && applySimulationCheck.isSelected()) {
            threat.internetFacing = false;
            if (threat.exploitAvailable) threat.exploitImpactFactor = 0.5;
            threat.calculateExplainableRisk(scoringConfig);
            String auditNote = "Virtual mitigation model committed: internal-only exposure; exploit impact at 50%.";
            threat.notes = threat.notes.isBlank() ? auditNote : threat.notes + "\n" + auditNote;
            simulateMitigationCheck.setSelected(false);
        }
        refreshTable();
        persistApplicationState();
    }

    private void deleteSelectedThreat() {
        int viewRow = threatTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Select a finding to delete.",
                "No Finding Selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = threatTable.convertRowIndexToModel(viewRow);
        Threat threat = threatList.get(modelRow);
        int result = JOptionPane.showConfirmDialog(this,
            "Delete " + threat.getId() + " — " + threat.getName() + "?",
            "Confirm Delete", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (result != JOptionPane.YES_OPTION) return;
        threatList.remove(modelRow);
        refreshTable();
        persistApplicationState();
    }

    private void clearAllFindings() {
        if (threatList.isEmpty()) return;
        int result = JOptionPane.showConfirmDialog(this,
            "Remove all " + threatList.size() + " findings from the queue?",
            "Confirm Clear All", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (result != JOptionPane.YES_OPTION) return;
        threatList.clear();
        refreshTable();
        persistApplicationState();
    }

    private void showScoringSettings() {
        JTextField cvssWeight = new JTextField(String.valueOf(scoringConfig.cvssWeight));
        JTextField criticalityWeight = new JTextField(String.valueOf(scoringConfig.criticalityWeight));
        JTextField exploitWeight = new JTextField(String.valueOf(scoringConfig.exploitWeight));
        JTextField exposureWeight = new JTextField(String.valueOf(scoringConfig.exposureWeight));
        JTextField criticalThreshold = new JTextField(String.valueOf(scoringConfig.criticalThreshold));
        JTextField highThreshold = new JTextField(String.valueOf(scoringConfig.highThreshold));
        JTextField mediumThreshold = new JTextField(String.valueOf(scoringConfig.mediumThreshold));

        JPanel fields = new JPanel(new GridLayout(0, 2, 8, 8));
        fields.add(new JLabel("CVSS weight"));
        fields.add(cvssWeight);
        fields.add(new JLabel("Asset criticality weight"));
        fields.add(criticalityWeight);
        fields.add(new JLabel("Active exploit weight"));
        fields.add(exploitWeight);
        fields.add(new JLabel("Internet exposure weight"));
        fields.add(exposureWeight);
        fields.add(new JLabel("Critical threshold"));
        fields.add(criticalThreshold);
        fields.add(new JLabel("High threshold"));
        fields.add(highThreshold);
        fields.add(new JLabel("Medium threshold"));
        fields.add(mediumThreshold);
        fields.add(new JLabel("Weights must total 100."));
        fields.add(new JLabel("Internal-only exposure earns 20% of its weight."));
        fields.add(new JLabel("Thresholds must descend."));
        fields.add(new JLabel("Below the medium threshold is Low."));

        int result = JOptionPane.showConfirmDialog(this, fields, "Risk Scoring Settings",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;
        try {
            double cvss = Double.parseDouble(cvssWeight.getText().trim());
            double criticality = Double.parseDouble(criticalityWeight.getText().trim());
            double exploit = Double.parseDouble(exploitWeight.getText().trim());
            double exposure = Double.parseDouble(exposureWeight.getText().trim());
            double critical = Double.parseDouble(criticalThreshold.getText().trim());
            double high = Double.parseDouble(highThreshold.getText().trim());
            double medium = Double.parseDouble(mediumThreshold.getText().trim());
            double weightTotal = cvss + criticality + exploit + exposure;
            if (!Double.isFinite(weightTotal) || cvss < 0 || criticality < 0 || exploit < 0
                || exposure < 0 || Math.abs(weightTotal - 100.0) > 0.001) {
                throw new IllegalArgumentException("Weights must be non-negative and total exactly 100.");
            }
            if (!Double.isFinite(critical) || !Double.isFinite(high) || !Double.isFinite(medium)
                || critical > 100 || critical <= high || high <= medium || medium < 0) {
                throw new IllegalArgumentException("Use thresholds from 0 to 100 in descending order.");
            }
            scoringConfig.cvssWeight = cvss;
            scoringConfig.criticalityWeight = criticality;
            scoringConfig.exploitWeight = exploit;
            scoringConfig.exposureWeight = exposure;
            scoringConfig.criticalThreshold = critical;
            scoringConfig.highThreshold = high;
            scoringConfig.mediumThreshold = medium;
            for (Threat threat : threatList) threat.calculateExplainableRisk(scoringConfig);
            refreshTable();
            persistApplicationState();
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage() == null
                ? "Enter valid numeric weights and thresholds." : ex.getMessage(),
                "Invalid Scoring Settings", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadPersistedState() {
        try {
            if (Files.exists(settingsFile)) loadScoringSettings();
        } catch (IOException | IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, "Could not load scoring settings; defaults will be used.\n"
                + ex.getMessage(), "Settings Load Error", JOptionPane.ERROR_MESSAGE);
        }
        if (Files.exists(findingsFile)) {
            try {
                threatList.addAll(readFindingsCsv(findingsFile));
            } catch (IOException | IllegalArgumentException ex) {
                threatList.clear();
                JOptionPane.showMessageDialog(this, "Could not load saved findings.\n" + ex.getMessage(),
                    "Saved Data Error", JOptionPane.ERROR_MESSAGE);
            }
        }
        refreshTable();
    }

    private void loadScoringSettings() throws IOException {
        Properties properties = new Properties();
        try (var input = Files.newInputStream(settingsFile)) {
            properties.load(input);
        }
        double cvss = Double.parseDouble(properties.getProperty("cvssWeight", "40"));
        double criticality = Double.parseDouble(properties.getProperty("criticalityWeight", "25"));
        double exploit = Double.parseDouble(properties.getProperty("exploitWeight", "20"));
        double exposure = Double.parseDouble(properties.getProperty("exposureWeight", "15"));
        double critical = Double.parseDouble(properties.getProperty("criticalThreshold", "80"));
        double high = Double.parseDouble(properties.getProperty("highThreshold", "60"));
        double medium = Double.parseDouble(properties.getProperty("mediumThreshold", "40"));
        if (!Double.isFinite(cvss + criticality + exploit + exposure)
            || cvss < 0 || criticality < 0 || exploit < 0 || exposure < 0
            || Math.abs(cvss + criticality + exploit + exposure - 100.0) > 0.001
            || !Double.isFinite(critical) || !Double.isFinite(high) || !Double.isFinite(medium)
            || critical > 100 || critical <= high || high <= medium || medium < 0) {
            throw new IllegalArgumentException("Saved risk-model settings are outside allowed ranges.");
        }
        scoringConfig.cvssWeight = cvss;
        scoringConfig.criticalityWeight = criticality;
        scoringConfig.exploitWeight = exploit;
        scoringConfig.exposureWeight = exposure;
        scoringConfig.criticalThreshold = critical;
        scoringConfig.highThreshold = high;
        scoringConfig.mediumThreshold = medium;
    }

    private void persistSettings() {
        Properties properties = new Properties();
        properties.setProperty("cvssWeight", String.valueOf(scoringConfig.cvssWeight));
        properties.setProperty("criticalityWeight", String.valueOf(scoringConfig.criticalityWeight));
        properties.setProperty("exploitWeight", String.valueOf(scoringConfig.exploitWeight));
        properties.setProperty("exposureWeight", String.valueOf(scoringConfig.exposureWeight));
        properties.setProperty("criticalThreshold", String.valueOf(scoringConfig.criticalThreshold));
        properties.setProperty("highThreshold", String.valueOf(scoringConfig.highThreshold));
        properties.setProperty("mediumThreshold", String.valueOf(scoringConfig.mediumThreshold));
        try {
            Files.createDirectories(appDataDirectory);
            try (var output = Files.newOutputStream(settingsFile)) {
                properties.store(output, "Cyber Threat Risk Dashboard");
            }
        } catch (IOException ex) {
            showStorageError("Could not save scoring settings", ex);
        }
    }

    private void persistFindings() {
        try {
            Files.createDirectories(appDataDirectory);
            Files.writeString(findingsFile, findingsCsv(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            showStorageError("Could not save findings", ex);
        }
    }

    private void persistApplicationState() {
        persistSettings();
        persistFindings();
    }

    private void showStorageError(String message, IOException ex) {
        JOptionPane.showMessageDialog(this, message + ":\n" + ex.getMessage(),
            "Storage Error", JOptionPane.ERROR_MESSAGE);
    }

    private String findingsCsv() {
        StringBuilder csv = new StringBuilder();
        appendCsvRow(csv, List.of("id", "name", "category", "cvss", "criticality", "exploitAvailable",
            "internetFacing", "status", "owner", "dueDate", "notes", "exploitImpactFactor"));
        for (Threat threat : threatList) {
            appendCsvRow(csv, List.of(threat.id, threat.name, threat.category, String.valueOf(threat.cvssScore),
                String.valueOf(threat.assetCriticality), String.valueOf(threat.exploitAvailable),
                String.valueOf(threat.internetFacing), threat.status, threat.owner, threat.dueDate,
                threat.notes, String.valueOf(threat.exploitImpactFactor)));
        }
        return csv.toString();
    }

    private void appendCsvRow(StringBuilder csv, List<String> values) {
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) csv.append(',');
            String value = values.get(i) == null ? "" : values.get(i);
            csv.append('"').append(value.replace("\"", "\"\"")).append('"');
        }
        csv.append("\r\n");
    }

    private List<Threat> readFindingsCsv(Path file) throws IOException {
        return readFindingsCsv(file, scoringConfig);
    }

    static List<Threat> readFindingsCsv(Path file, RiskScoringConfig scoringConfig) throws IOException {
        List<List<String>> rows = parseCsv(Files.readString(file, StandardCharsets.UTF_8));
        List<String> baseHeader = List.of("id", "name", "category", "cvss", "criticality",
            "exploitAvailable", "internetFacing", "status", "owner", "dueDate", "notes");
        List<String> currentHeader = new ArrayList<>(baseHeader);
        currentHeader.add("exploitImpactFactor");
        if (rows.isEmpty() || (!rows.get(0).equals(baseHeader) && !rows.get(0).equals(currentHeader))) {
            throw new IllegalArgumentException("CSV header does not match the supported findings format.");
        }
        boolean hasImpactFactor = rows.get(0).equals(currentHeader);
        int expectedFieldCount = hasImpactFactor ? currentHeader.size() : baseHeader.size();
        List<Threat> loaded = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (int row = 1; row < rows.size(); row++) {
            List<String> values = rows.get(row);
            if (values.size() != expectedFieldCount) {
                throw new IllegalArgumentException("CSV row " + (row + 1) + " must contain "
                    + expectedFieldCount + " fields.");
            }
            String id = values.get(0).trim();
            String name = values.get(1).trim();
            String category = values.get(2).trim();
            double cvss = Double.parseDouble(values.get(3));
            int criticality = Integer.parseInt(values.get(4));
            if (id.isEmpty() || name.isEmpty() || category.isEmpty() || !Double.isFinite(cvss)
                || cvss < 0 || cvss > 10 || criticality < 1 || criticality > 5) {
                throw new IllegalArgumentException("CSV row " + (row + 1) + " contains invalid required values.");
            }
            if (!ids.add(id.toLowerCase(Locale.ROOT))) {
                throw new IllegalArgumentException("Duplicate finding ID in CSV: " + id);
            }
            boolean exploit = parseBoolean(values.get(5), row);
            boolean internetFacing = parseBoolean(values.get(6), row);
            String status = values.get(7);
            if (!List.of("Open", "In Progress", "Resolved").contains(status)) {
                throw new IllegalArgumentException("CSV row " + (row + 1) + " has an invalid remediation status.");
            }
            String dueDate = values.get(9);
            try {
                if (!dueDate.isBlank()) LocalDate.parse(dueDate);
            } catch (DateTimeParseException ex) {
                throw new IllegalArgumentException("CSV row " + (row + 1) + " has an invalid due date.", ex);
            }
            Threat threat = new Threat(id, name, category, cvss, criticality, exploit, internetFacing, scoringConfig);
            if (hasImpactFactor) {
                double factor = Double.parseDouble(values.get(11));
                if (!Double.isFinite(factor) || factor < 0 || factor > 1) {
                    throw new IllegalArgumentException("CSV row " + (row + 1) + " has an invalid exploit impact factor.");
                }
                threat.exploitImpactFactor = factor;
                threat.calculateExplainableRisk(scoringConfig);
            }
            threat.status = status;
            threat.owner = values.get(8);
            threat.dueDate = dueDate;
            threat.notes = values.get(10);
            loaded.add(threat);
        }
        return loaded;
    }

    private static boolean parseBoolean(String value, int row) {
        if ("true".equalsIgnoreCase(value)) return true;
        if ("false".equalsIgnoreCase(value)) return false;
        throw new IllegalArgumentException("CSV row " + (row + 1) + " has an invalid boolean value.");
    }

    static List<List<String>> parseCsv(String text) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder cell = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < text.length(); i++) {
            char current = text.charAt(i);
            if (quoted) {
                if (current == '"' && i + 1 < text.length() && text.charAt(i + 1) == '"') {
                    cell.append('"');
                    i++;
                } else if (current == '"') {
                    quoted = false;
                } else {
                    cell.append(current);
                }
            } else if (current == '"' && cell.length() == 0) {
                quoted = true;
            } else if (current == ',') {
                row.add(cell.toString());
                cell.setLength(0);
            } else if (current == '\n' || current == '\r') {
                if (!row.isEmpty() || cell.length() > 0) {
                    row.add(cell.toString());
                    rows.add(row);
                }
                cell.setLength(0);
                row = new ArrayList<>();
                if (current == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n') i++;
            } else if (cell.length() > 0 || !Character.isWhitespace(current)) {
                cell.append(current);
            }
        }
        if (quoted) throw new IllegalArgumentException("CSV contains an unclosed quoted field.");
        if (cell.length() > 0 || !row.isEmpty()) {
            row.add(cell.toString());
            rows.add(row);
        }
        return rows;
    }

    private void importCsv() {
        JFileChooser chooser = createUserFileChooser("Import Findings CSV", null);
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("CSV files (*.csv)", "csv"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            List<Threat> imported = readFindingsCsv(chooser.getSelectedFile().toPath());
            Set<String> existingIds = new HashSet<>();
            for (Threat threat : threatList) existingIds.add(threat.getId().toLowerCase(Locale.ROOT));
            int added = 0;
            int skipped = 0;
            for (Threat threat : imported) {
                if (existingIds.add(threat.getId().toLowerCase(Locale.ROOT))) {
                    threatList.add(threat);
                    added++;
                } else {
                    skipped++;
                }
            }
            refreshTable();
            persistApplicationState();
            JOptionPane.showMessageDialog(this, "Import complete. Added " + added
                + " finding(s); skipped " + skipped + " duplicate ID(s).",
                "CSV Import", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException | IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, "CSV import failed:\n" + ex.getMessage(),
                "Import Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportCsv() {
        JFileChooser chooser = createUserFileChooser("Export Findings CSV", "cyber-threat-findings.csv");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("CSV files (*.csv)", "csv"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path target = chooser.getSelectedFile().toPath();
        try {
            Files.writeString(target, findingsCsv(), StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this, "Findings exported to:\n" + target.toAbsolutePath(),
                "CSV Export", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            showStorageError("Could not export findings", ex);
        }
    }

    private JFileChooser createUserFileChooser(String title, String defaultFileName) {
        Path home = Paths.get(System.getProperty("user.home"));
        Path initialDirectory = home;
        for (String folder : List.of("Documents", "Desktop")) {
            Path candidate = home.resolve(folder);
            if (Files.isDirectory(candidate)) {
                initialDirectory = candidate;
                break;
            }
        }
        JFileChooser chooser = new JFileChooser(initialDirectory.toFile());
        chooser.setDialogTitle(title);
        if (defaultFileName != null) {
            chooser.setSelectedFile(initialDirectory.resolve(defaultFileName).toFile());
        }
        return chooser;
    }

    private JPanel createMetricCard(String title, JLabel value, String detail, Color accent) {
        JPanel card = new JPanel(new GridLayout(3, 1, 0, 2));
        card.setBackground(Color.WHITE);
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 4, 0, 0, accent),
            BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(226, 232, 240)),
                BorderFactory.createEmptyBorder(8, 12, 8, 8)
            )
        ));
        JLabel titleLabel = new JLabel(title);
        titleLabel.setForeground(new Color(100, 116, 139));
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 11f));
        value.setForeground(new Color(15, 23, 42));
        value.setFont(value.getFont().deriveFont(Font.BOLD, 22f));
        JLabel detailLabel = new JLabel(detail);
        detailLabel.setForeground(new Color(100, 116, 139));
        detailLabel.setFont(detailLabel.getFont().deriveFont(10f));
        card.add(titleLabel);
        card.add(value);
        card.add(detailLabel);
        return card;
    }

    private void updateSummaryCards() {
        int criticalCount = 0;
        int highCount = 0;
        double totalRisk = 0.0;
        for (Threat threat : threatList) {
            totalRisk += threat.getFinalRiskScore();
            if ("CRITICAL".equals(threat.getPriorityLevel())) {
                criticalCount++;
            } else if ("HIGH".equals(threat.getPriorityLevel())) {
                highCount++;
            }
        }
        totalCountValue.setText(String.valueOf(threatList.size()));
        criticalCountValue.setText(String.valueOf(criticalCount));
        highCountValue.setText(String.valueOf(highCount));
        averageRiskValue.setText(String.format("%.1f", threatList.isEmpty()
            ? 0.0 : totalRisk / threatList.size()));
    }

    private String buildThreatDetails(Threat threat) {
        StringBuilder details = new StringBuilder(threat.getExplanationText());
        if (simulateMitigationCheck.isSelected()) {
            Threat preview = threat.createMitigatedPreview(scoringConfig);
            double scoreDrop = threat.getFinalRiskScore() - preview.getFinalRiskScore();
            details.append("\n\nMITIGATION SIMULATION (PREVIEW ONLY)\n");
            details.append(String.format(Locale.ROOT,
                "Simulated Score: %.1f \u2192 %.1f [-%.1f pts]\n",
                threat.getFinalRiskScore(), preview.getFinalRiskScore(), scoreDrop));
            details.append("This preview is not saved. Use Update Remediation to commit it.\n");
        }
        details.append("\n\nREMEDIATION TRACKING\n");
        details.append("Status: ").append(threat.status).append("\n");
        details.append("Owner: ").append(threat.owner.isBlank() ? "Unassigned" : threat.owner).append("\n");
        details.append("Due date: ").append(threat.dueDate.isBlank() ? "Not set" : threat.dueDate).append("\n");
        if (!threat.notes.isBlank()) details.append("Notes: ").append(threat.notes).append("\n");
        return details.toString();
    }

    private void updateSelectedThreatView() {
        int viewRow = threatTable.getSelectedRow();
        if (viewRow < 0) {
            explanationArea.setText("");
            visualPanel.setThreat(null, null);
            return;
        }
        int modelRow = threatTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= threatList.size()) return;
        Threat threat = threatList.get(modelRow);
        Threat preview = simulateMitigationCheck.isSelected()
            ? threat.createMitigatedPreview(scoringConfig) : null;
        explanationArea.setText(buildThreatDetails(threat));
        visualPanel.setThreat(threat, preview);
    }

    private void exportReport() {
        JFileChooser chooser = createUserFileChooser(
            "Export Prioritization Report", "cyber-threat-prioritization-report.txt");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Text files (*.txt)", "txt"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path target = chooser.getSelectedFile().toPath();
        try {
            Files.writeString(target, buildReport(), StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this, "Report exported to:\n" + target.toAbsolutePath(),
                "Report Export", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            showStorageError("Could not export report", ex);
        }
    }

    private String buildReport() {
        StringBuilder report = new StringBuilder();
        report.append("CYBER THREAT RISK PRIORITIZATION REPORT\n");
        report.append("Decision-support estimate; not a verified prediction or live alert.\n");
        report.append("Generated: ").append(LocalDateTime.now().format(
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("\n");
        report.append("Findings: ").append(threatList.size())
            .append(" | Critical: ").append(countByPriority("CRITICAL"))
            .append(" | High: ").append(countByPriority("HIGH"))
            .append(" | Open: ").append(countByStatus("Open"))
            .append(" | In progress: ").append(countByStatus("In Progress"))
            .append(" | Resolved: ").append(countByStatus("Resolved")).append("\n");
        report.append(String.format(Locale.ROOT,
            "Model weights: CVSS %.1f%%, asset criticality %.1f%%, active exploit %.1f%%, exposure %.1f%%\n",
            scoringConfig.cvssWeight, scoringConfig.criticalityWeight,
            scoringConfig.exploitWeight, scoringConfig.exposureWeight));
        report.append("Internal-only findings receive 20% of the exposure weight.\n");
        report.append(String.format(Locale.ROOT,
            "Priority thresholds: Critical >= %.1f, High >= %.1f, Medium >= %.1f\n\n",
            scoringConfig.criticalThreshold, scoringConfig.highThreshold, scoringConfig.mediumThreshold));
        int rank = 1;
        for (Threat threat : threatList) {
            report.append("RANK #").append(rank++).append(" | STATUS: ").append(threat.status).append("\n");
            report.append(threat.getExplanationText()).append("\n");
            report.append("REMEDIATION OWNER: ").append(threat.owner.isBlank() ? "Unassigned" : threat.owner).append("\n");
            report.append("DUE DATE: ").append(threat.dueDate.isBlank() ? "Not set" : threat.dueDate).append("\n");
            if (!threat.notes.isBlank()) report.append("NOTES: ").append(threat.notes).append("\n");
            report.append("\n").append("=".repeat(72)).append("\n\n");
        }
        return report.toString();
    }

    private long countByPriority(String priority) {
        return threatList.stream().filter(threat -> priority.equals(threat.getPriorityLevel())).count();
    }

    private long countByStatus(String status) {
        return threatList.stream().filter(threat -> status.equals(threat.status)).count();
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ex) {
            System.err.println("Could not apply the system look and feel; using the default UI.");
            ex.printStackTrace(System.err);
        }
        applyApplicationFont();
        SwingUtilities.invokeLater(() -> new CyberThreatApp().setVisible(true));
    }

    private static void applyApplicationFont() {
        UIDefaults defaults = UIManager.getDefaults();
        for (Object key : defaults.keySet()) {
            Object value = defaults.get(key);
            if (value instanceof Font font) {
                defaults.put(key, new FontUIResource("Avenir Next", font.getStyle(), font.getSize()));
            }
        }
    }

    // =========================================================================
    // INNER CLASS 1: Threat Data Model & Explainable AI (XAI) Scoring Engine
    // =========================================================================
    static class Threat {
        private String id;
        private String name;
        private String category;
        private double cvssScore;       // 0.0 to 10.0
        private int assetCriticality;   // 1 to 5
        private boolean exploitAvailable;
        private boolean internetFacing;
        private double exploitImpactFactor = 1.0;
        private String status = "Open";
        private String owner = "";
        private String dueDate = "";
        private String notes = "";
        
        private double finalRiskScore;
        private String priorityLevel;
        private Map<String, Double> featureContributions;
        private String explanationText;

        public Threat(String id, String name, String category, double cvssScore, 
                      int assetCriticality, boolean exploitAvailable, boolean internetFacing,
                      RiskScoringConfig scoringConfig) {
            this.id = id;
            this.name = name;
            this.category = category;
            this.cvssScore = cvssScore;
            this.assetCriticality = assetCriticality;
            this.exploitAvailable = exploitAvailable;
            this.internetFacing = internetFacing;
            this.featureContributions = new LinkedHashMap<>();
            calculateExplainableRisk(scoringConfig);
        }

        private void calculateExplainableRisk(RiskScoringConfig config) {
            featureContributions.clear();
            double cvssImpact = (cvssScore / 10.0) * config.cvssWeight;
            double assetImpact = (assetCriticality / 5.0) * config.criticalityWeight;
            double exploitImpact = exploitAvailable ? config.exploitWeight * exploitImpactFactor : 0.0;
            double exposureImpact = internetFacing ? config.exposureWeight : config.exposureWeight * 0.2;

            this.finalRiskScore = Math.round((cvssImpact + assetImpact + exploitImpact + exposureImpact) * 10.0) / 10.0;

            featureContributions.put("CVSS Base Severity (" + cvssScore + "/10)", Math.round(cvssImpact * 10.0) / 10.0);
            featureContributions.put("Asset Criticality (Level " + assetCriticality + "/5)", Math.round(assetImpact * 10.0) / 10.0);
            String exploitLabel = exploitAvailable
                ? (exploitImpactFactor < 1.0 ? "Yes, impact " + (int) (exploitImpactFactor * 100) + "%" : "Yes")
                : "No";
            featureContributions.put("Active Exploit in Wild (" + exploitLabel + ")", exploitImpact);
            featureContributions.put("Network Exposure (" + (internetFacing ? "External/Internet" : "Internal") + ")", exposureImpact);

            if (finalRiskScore >= config.criticalThreshold) {
                priorityLevel = "CRITICAL";
            } else if (finalRiskScore >= config.highThreshold) {
                priorityLevel = "HIGH";
            } else if (finalRiskScore >= config.mediumThreshold) {
                priorityLevel = "MEDIUM";
            } else {
                priorityLevel = "LOW";
            }

            StringBuilder sb = new StringBuilder();
            sb.append("VULNERABILITY: ").append(id).append(" - ").append(name).append("\n");
            sb.append("CATEGORY: ").append(category).append("\n");
            sb.append("RISK SCORE: ").append(finalRiskScore).append(" / 100  |  PRIORITY: ").append(priorityLevel).append("\n");
            sb.append("ASSESSMENT: CVSS ").append(cvssScore).append("/10  |  Asset criticality ")
                .append(assetCriticality).append("/5  |  Active exploit ")
                .append(exploitAvailable ? "Yes" : "No").append("  |  ")
                .append(internetFacing ? "Internet-facing" : "Internal-only").append("\n");
            sb.append("MODEL WEIGHTS: CVSS ").append(config.cvssWeight).append("%, asset ")
                .append(config.criticalityWeight).append("%, exploit ").append(config.exploitWeight)
                .append("%, exposure ").append(config.exposureWeight).append("%\n");
            sb.append("------------------------------------------------------------\n");
            sb.append("RISK FACTOR CONTRIBUTIONS (POINTS OUT OF 100; PERCENTAGE OF THIS SCORE):\n");
            for (Map.Entry<String, Double> entry : featureContributions.entrySet()) {
                double pct = finalRiskScore == 0.0 ? 0.0 : (entry.getValue() / finalRiskScore) * 100.0;
                sb.append(String.format(" • %-38s : +%.1f pts (%.1f%% impact)\n", entry.getKey(), entry.getValue(), pct));
            }
            sb.append("\nRECOMMENDED RESPONSE:\n");
            if (priorityLevel.equals("CRITICAL")) {
                sb.append(" -> IMMEDIATE PATCHING REQUIRED within 24 hours. Isolate affected nodes if external-facing.");
            } else if (priorityLevel.equals("HIGH")) {
                sb.append(" -> Schedule urgent remediation within 72 hours and enable IDS/IPS signatures.");
            } else if (priorityLevel.equals("MEDIUM")) {
                sb.append(" -> Include in next regular maintenance patch cycle and monitor logs.");
            } else {
                sb.append(" -> Routine monitoring; low immediate operational risk.");
            }
            this.explanationText = sb.toString();
        }

        public String getId() { return id; }
        public String getName() { return name; }
        public String getCategory() { return category; }
        public double getCvssScore() { return cvssScore; }
        public double getFinalRiskScore() { return finalRiskScore; }
        public String getPriorityLevel() { return priorityLevel; }
        public Map<String, Double> getFeatureContributions() { return featureContributions; }
        public String getExplanationText() { return explanationText; }

        private Threat createMitigatedPreview(RiskScoringConfig config) {
            Threat preview = new Threat(id, name, category, cvssScore, assetCriticality,
                exploitAvailable, false, config);
            preview.exploitImpactFactor = exploitAvailable ? Math.min(exploitImpactFactor, 0.5) : exploitImpactFactor;
            preview.calculateExplainableRisk(config);
            return preview;
        }
    }

    static class RiskScoringConfig {
        private double cvssWeight = 40;
        private double criticalityWeight = 25;
        private double exploitWeight = 20;
        private double exposureWeight = 15;
        private double criticalThreshold = 80;
        private double highThreshold = 60;
        private double mediumThreshold = 40;
    }

    // =========================================================================
    // INNER CLASS 2: Graphical analysis dashboard
    // =========================================================================
    static class GraphDashboardPanel extends JPanel {
        private static final long serialVersionUID = 1L;

        private final BarChartPanel cvssChart = new BarChartPanel("CVSS Severity Distribution");
        private final BarChartPanel priorityChart = new BarChartPanel("Priority Distribution");
        private final BarChartPanel criticalityChart = new BarChartPanel("Asset Criticality");
        private final BarChartPanel exposureChart = new BarChartPanel("Exploit & Exposure Signals");

        GraphDashboardPanel() {
            setBackground(new Color(248, 250, 252));
            setLayout(new GridLayout(2, 2, 10, 10));
            setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
            add(cvssChart);
            add(priorityChart);
            add(criticalityChart);
            add(exposureChart);
        }

        void updateGraphs(List<Threat> threats) {
            String[] cvssLabels = {"Low", "Medium", "High", "Critical"};
            int[] cvssValues = {0, 0, 0, 0};
            String[] priorityLabels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"};
            int[] priorityValues = {0, 0, 0, 0};
            String[] criticalityLabels = {"Level 1", "Level 2", "Level 3", "Level 4", "Level 5"};
            int[] criticalityValues = new int[5];
            int activeExploit = 0;
            int noExploit = 0;
            int internetFacing = 0;
            int internalOnly = 0;

            for (Threat threat : threats) {
                double cvss = threat.cvssScore;
                if (cvss < 4.0) cvssValues[0]++;
                else if (cvss < 7.0) cvssValues[1]++;
                else if (cvss < 9.0) cvssValues[2]++;
                else cvssValues[3]++;

                if ("CRITICAL".equals(threat.priorityLevel)) priorityValues[0]++;
                else if ("HIGH".equals(threat.priorityLevel)) priorityValues[1]++;
                else if ("MEDIUM".equals(threat.priorityLevel)) priorityValues[2]++;
                else priorityValues[3]++;

                int criticalityIndex = Math.max(0, Math.min(4, threat.assetCriticality - 1));
                criticalityValues[criticalityIndex]++;

                if (threat.exploitAvailable) activeExploit++;
                else noExploit++;
                if (threat.internetFacing) internetFacing++;
                else internalOnly++;
            }

            cvssChart.setData(cvssLabels, cvssValues,
                new Color[]{new Color(34, 197, 94), new Color(234, 179, 8),
                    new Color(249, 115, 22), new Color(220, 38, 38)});
            priorityChart.setData(priorityLabels, priorityValues,
                new Color[]{new Color(220, 38, 38), new Color(234, 88, 12),
                    new Color(202, 138, 4), new Color(34, 197, 94)});
            criticalityChart.setData(criticalityLabels, criticalityValues,
                new Color[]{new Color(191, 219, 254), new Color(147, 197, 253),
                    new Color(96, 165, 250), new Color(59, 130, 246),
                    new Color(37, 99, 235)});
            exposureChart.setData(
                new String[]{"Exploit: Yes", "Exploit: No", "Internet", "Internal"},
                new int[]{activeExploit, noExploit, internetFacing, internalOnly},
                new Color[]{new Color(220, 38, 38), new Color(148, 163, 184),
                    new Color(13, 148, 136), new Color(96, 165, 250)});
        }

        static class BarChartPanel extends JPanel {
            private static final long serialVersionUID = 1L;

            private final String title;
            private String[] labels = new String[0];
            private int[] values = new int[0];
            private Color[] colors = new Color[0];

            BarChartPanel(String title) {
                this.title = title;
                setBackground(Color.WHITE);
                setBorder(BorderFactory.createTitledBorder(title));
            }

            void setData(String[] labels, int[] values, Color[] colors) {
                this.labels = labels;
                this.values = values;
                this.colors = colors;
                repaint();
            }

            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                if (labels.length == 0) return;

                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setFont(new Font("Avenir Next", Font.PLAIN, 12));

                int maxValue = 1;
                for (int value : values) maxValue = Math.max(maxValue, value);

                int chartX = 145;
                int chartWidth = Math.max(40, getWidth() - chartX - 55);
                int rowHeight = 28;
                int startY = 30;

                for (int i = 0; i < labels.length; i++) {
                    int y = startY + i * rowHeight;
                    g2.setColor(new Color(51, 65, 85));
                    g2.drawString(labels[i], 12, y + 16);

                    int barWidth = (int) ((values[i] / (double) maxValue) * chartWidth);
                    g2.setColor(colors[i % colors.length]);
                    g2.fillRoundRect(chartX, y + 2, Math.max(barWidth, values[i] > 0 ? 4 : 0), 18, 5, 5);

                    g2.setColor(new Color(30, 41, 59));
                    g2.setFont(g2.getFont().deriveFont(Font.BOLD));
                    g2.drawString(String.valueOf(values[i]), chartX + Math.max(barWidth, 4) + 8, y + 16);
                    g2.setFont(new Font("Avenir Next", Font.PLAIN, 12));
                }
                g2.dispose();
            }
        }
    }

    // =========================================================================
    // INNER CLASS 3: Custom SHAP-Style Visual Attribution Bar Chart
    // =========================================================================
    static class XAIVisualPanel extends JPanel {
        private static final long serialVersionUID = 1L;

        private Threat selectedThreat;
        private Threat previewThreat;

        public XAIVisualPanel() {
            setBackground(new Color(240, 249, 255));
            setBorder(BorderFactory.createTitledBorder("Weighted Risk Factor Contributions"));
        }

        public void setThreat(Threat threat, Threat preview) {
            this.selectedThreat = threat;
            this.previewThreat = preview;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (selectedThreat == null) {
                g.setColor(Color.GRAY);
                g.drawString("Select a threat from the table to inspect AI feature weights.", 20, 40);
                return;
            }

            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            Map<String, Double> contributions = previewThreat == null
                ? selectedThreat.getFeatureContributions() : previewThreat.getFeatureContributions();
            int y = 35;
            if (previewThreat != null) {
                g2.setColor(new Color(13, 148, 136));
                g2.setFont(new Font("Avenir Next", Font.BOLD, 11));
                g2.drawString("SIMULATION PREVIEW — not committed", 15, 25);
                y += 14;
            }
            int barMaxWidth = getWidth() - 310;
            if (barMaxWidth < 40) barMaxWidth = 40;
            double maxContribution = Math.max(1.0, contributions.values().stream()
                .mapToDouble(Double::doubleValue).max().orElse(1.0));
            int availableBarWidth = Math.max(1, barMaxWidth - 65);

            Color[] barColors = {
                new Color(220, 38, 38),
                new Color(234, 88, 12),
                new Color(37, 99, 235),
                new Color(13, 148, 136)
            };

            int idx = 0;
            for (Map.Entry<String, Double> entry : contributions.entrySet()) {
                g2.setColor(Color.DARK_GRAY);
                g2.setFont(new Font("Avenir Next", Font.BOLD, 12));
                String label = entry.getKey();
                FontMetrics metrics = g2.getFontMetrics();
                while (label.length() > 3 && metrics.stringWidth(label) > 220) {
                    label = label.substring(0, label.length() - 4) + "...";
                }
                g2.drawString(label, 15, y + 14);

                int barWidth = (int) ((entry.getValue() / maxContribution) * availableBarWidth);
                g2.setColor(barColors[idx % barColors.length]);
                g2.fillRoundRect(245, y, Math.max(barWidth, 4), 20, 6, 6);

                g2.setColor(Color.BLACK);
                g2.drawString("+" + entry.getValue() + " pts", 253 + Math.max(barWidth, 4), y + 14);

                y += 34;
                idx++;
            }
        }
    }

    static class HeaderIllustration extends JPanel {
        private static final long serialVersionUID = 1L;

        HeaderIllustration() {
            setOpaque(false);
            setPreferredSize(new Dimension(150, 76));
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int x = getWidth() - 68;
            int y = 8;
            Polygon shield = new Polygon(
                new int[]{x, x + 24, x + 24, x + 12, x, x - 1},
                new int[]{y, y + 5, y + 28, y + 42, y + 28, y + 5},
                6
            );
            g2.setColor(new Color(45, 212, 191));
            g2.fill(shield);
            g2.setColor(new Color(15, 23, 42));
            g2.setStroke(new BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.drawLine(x + 6, y + 20, x + 11, y + 25);
            g2.drawLine(x + 11, y + 25, x + 19, y + 14);

            int[][] nodes = {{x - 24, y + 9}, {x - 35, y + 25}, {x - 23, y + 37},
                             {x + 39, y + 11}, {x + 45, y + 31}};
            g2.setColor(new Color(129, 140, 248));
            g2.setStroke(new BasicStroke(2f));
            for (int[] node : nodes) {
                g2.drawLine(x + 12, y + 22, node[0] + 4, node[1] + 4);
                g2.fillOval(node[0], node[1], 8, 8);
            }
            g2.setColor(new Color(251, 191, 36));
            g2.fillOval(x - 3, y + 4, 7, 7);
            g2.fillOval(x + 21, y + 32, 7, 7);
            g2.dispose();
        }
    }
}