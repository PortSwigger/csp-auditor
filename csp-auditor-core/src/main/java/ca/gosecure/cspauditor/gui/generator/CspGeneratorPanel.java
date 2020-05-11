package ca.gosecure.cspauditor.gui.generator;

import com.esotericsoftware.minlog.Log;
import main.java.ca.gosecure.cspauditor.gui.generator.SortedUniqueComboBoxModel;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Collection;
import java.util.Vector;

public class CspGeneratorPanel {
    private JButton analyseButton;
    private JComboBox comboBox1;
    private JPanel rootPanel;
    private JButton refreshButton;
    private JTabbedPane resultTabbedPane;
    private JPanel configurationPanel;
    private JPanel inlineScriptPanel;
    private JTable resourcesTable;
    private JPanel resourcePanel;
    private JTable inlinesTable;
    private JPanel inlinePanel;
    private JPanel configTabPanel;
    private JTable reportsTable;
    private JPanel reportPanel;
    private JTextPane warningConfigurationTextPane;

    DefaultTableModel tableResourcesModel = new DefaultTableModel() {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    DefaultTableModel tableInlinesModel = new DefaultTableModel() {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    DefaultTableModel reportsModel = new DefaultTableModel() {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };


    private CspGeneratorPanelController controller;
    //private CspGeneratorPanelUiProvider uiProvider;

    public CspGeneratorPanel(CspGeneratorPanelController controller) {
        this.controller = controller;
        //this.uiProvider = uiProvider;

    }

    public void init() {


        //Resources table
        tableResourcesModel.addColumn("id");
        tableResourcesModel.addColumn("Request");
        tableResourcesModel.addColumn("Type");
        resourcesTable.setModel(tableResourcesModel);
        resourcesTable.getColumnModel().getColumn(0).setMaxWidth(45);

        resourcesTable.getSelectionModel().addListSelectionListener((ListSelectionEvent event) -> {
            int viewRow = resourcesTable.getSelectedRow();
            if(viewRow == -1) return;

            Vector values = (Vector) tableResourcesModel.getDataVector().get(viewRow);
            selectResourceItem((String) values.get(0));
        });

        //Inlines table
        tableInlinesModel.addColumn("id");
        tableInlinesModel.addColumn("Request");
        tableInlinesModel.addColumn("Code");
        inlinesTable.setModel(tableInlinesModel);
        inlinesTable.getColumnModel().getColumn(0).setMaxWidth(45);

        inlinesTable.getSelectionModel().addListSelectionListener((ListSelectionEvent event) -> {
            int viewRow = inlinesTable.getSelectedRow();
            if(viewRow == -1) return;
            Vector values = (Vector) tableInlinesModel.getDataVector().get(viewRow);
            selectInlineItem((String) values.get(0));
        });


        //Report table
        reportsModel.addColumn("id");
        reportsModel.addColumn("blocked-uri");
        reportsModel.addColumn("document-uri");
        reportsModel.addColumn("original-policy");
        reportsModel.addColumn("violated-directive");
        reportsTable.setModel(reportsModel);
        reportsTable.getColumnModel().getColumn(0).setMaxWidth(45);

        reportsTable.getSelectionModel().addListSelectionListener((ListSelectionEvent event) -> {
            int viewRow = reportsTable.getSelectedRow();
            if(viewRow == -1) return;

            Vector values = (Vector) reportsModel.getDataVector().get(viewRow);
            selectReportItem((String) values.get(0));
        });

        //Analyze
        analyseButton.addActionListener((ActionEvent e) -> {
            String value = (String) comboBox1.getSelectedItem();
            if (value != null)
                controller.analyzeDomain(value);
        });


        //Refresh button
        this.refreshButton.setText("\u21BB");
        refreshButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                controller.refreshDomains();
            }
        });

        this.warningConfigurationTextPane.addHyperlinkListener(e -> {
            if(e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                if (Desktop.isDesktopSupported()) {
                    try {
                        Desktop.getDesktop().browse(e.getURL().toURI());
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                } else {
                    System.out.println(e.getURL().toString()+" clicked");
                }
            }
        });
    }

    private void selectReportItem(String id) {
        controller.selectReport(id);
    }

    public JPanel getRootPanel() {
        return rootPanel;
    }

    ////Domains

    public void clearDomains() {
        comboBox1.removeAll();
    }

    public void addDomains(Collection<String> domains) {
        for (String domain : domains) {
            comboBox1.addItem(domain);
        }
    }

    public void addDomain(String domain) {
        comboBox1.addItem(domain);
    }

    ////Configurations

    public void setConfiguration(Component configuration) {
        configurationPanel.removeAll();
        configurationPanel.add(configuration);
    }

    ////Resources

    public void clearResources() {
        tableResourcesModel.setRowCount(0);
    }

    public void addResource(String id, String url, String type) {
        Log.debug("Adding resource " + url);
        tableResourcesModel.addRow(new String[]{id, url, type});
    }

    public void selectResourceItem(String path) {
        controller.selectResource(path);
    }

    public void setResourceItem(Component resource) {
        resourcePanel.removeAll();
        resourcePanel.add(resource);
    }

    ////Inlines scripts

    public void clearInlineScript() {
        tableInlinesModel.setRowCount(0);
    }

    public void addInlineScript(String id, String urlString, String line) {
        Log.debug("Adding inline script from " + urlString);
        tableInlinesModel.addRow(new String[]{id, urlString, line});
    }

    public void selectInlineItem(String path) {
        controller.selectInline(path);
    }

    public void setInlineItem(Component resource) {
        inlinePanel.removeAll();
        inlinePanel.add(resource);
    }

    ////Reports

    public void setReportItem(Component resource) {
        reportPanel.removeAll();
        reportPanel.add(resource);
    }


    public void addReport(String id, String blockedUri, String documentUri, String originalPolicy, String violatedDirective) {
        reportsModel.addRow(new String[]{id, blockedUri, documentUri,originalPolicy,violatedDirective});
    }

    public void clearReports() {
        reportsModel.setRowCount(0);
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        rootPanel = new JPanel();
        rootPanel.setLayout(new BorderLayout(0, 0));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new BorderLayout(0, 0));
        rootPanel.add(panel1, BorderLayout.CENTER);
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new BorderLayout(0, 0));
        panel2.setEnabled(true);
        panel1.add(panel2, BorderLayout.NORTH);
        comboBox1 = new JComboBox();
        comboBox1.setModel(new SortedUniqueComboBoxModel());
        panel2.add(comboBox1, BorderLayout.CENTER);
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
        panel2.add(panel3, BorderLayout.EAST);
        refreshButton = new JButton();
        refreshButton.setText("Refresh");
        panel3.add(refreshButton);
        analyseButton = new JButton();
        analyseButton.setHideActionText(true);
        analyseButton.setText("Analyze");
        panel3.add(analyseButton);
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new BorderLayout(0, 0));
        panel1.add(panel4, BorderLayout.CENTER);
        resultTabbedPane = new JTabbedPane();
        resultTabbedPane.setTabLayoutPolicy(0);
        panel4.add(resultTabbedPane, BorderLayout.CENTER);
        configTabPanel = new JPanel();
        configTabPanel.setLayout(new BorderLayout(0, 0));
        resultTabbedPane.addTab("Configuration", configTabPanel);
        configurationPanel = new JPanel();
        configurationPanel.setLayout(new BorderLayout(0, 0));
        configTabPanel.add(configurationPanel, BorderLayout.CENTER);
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new BorderLayout(0, 0));
        configTabPanel.add(panel5, BorderLayout.SOUTH);
        warningConfigurationTextPane = new JTextPane();
        warningConfigurationTextPane.setEditable(false);
        warningConfigurationTextPane.setContentType("text/html");
        warningConfigurationTextPane.setText("<html>   <head>        </head>   <body>     <b>Warning</b>: Refer to &quot;Inline Scripts&quot; to see scripts that are not      compatible with CSP strict mode (Directive &quot;script-src 'unsafe-inline'&quot; is not included.).<br><a href=\"https://www.gosecure.net/blog/2016/06/28/auditing-csp-headers-with-burp-and-zap/#passives-rules\">More      information on CSP pitfalls</a>   </body> </html> ");
        panel5.add(warningConfigurationTextPane, BorderLayout.CENTER);
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new BorderLayout(0, 0));
        resultTabbedPane.addTab("External Resources", panel6);
        final JSplitPane splitPane1 = new JSplitPane();
        splitPane1.setOrientation(0);
        panel6.add(splitPane1, BorderLayout.CENTER);
        resourcePanel = new JPanel();
        resourcePanel.setLayout(new BorderLayout(0, 0));
        splitPane1.setRightComponent(resourcePanel);
        final JScrollPane scrollPane1 = new JScrollPane();
        splitPane1.setLeftComponent(scrollPane1);
        resourcesTable = new JTable();
        scrollPane1.setViewportView(resourcesTable);
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new BorderLayout(0, 0));
        resultTabbedPane.addTab("Inline Scripts", panel7);
        final JSplitPane splitPane2 = new JSplitPane();
        splitPane2.setOrientation(0);
        panel7.add(splitPane2, BorderLayout.CENTER);
        final JScrollPane scrollPane2 = new JScrollPane();
        splitPane2.setLeftComponent(scrollPane2);
        inlinesTable = new JTable();
        scrollPane2.setViewportView(inlinesTable);
        inlinePanel = new JPanel();
        inlinePanel.setLayout(new BorderLayout(0, 0));
        splitPane2.setRightComponent(inlinePanel);
        final JPanel panel8 = new JPanel();
        panel8.setLayout(new BorderLayout(0, 0));
        resultTabbedPane.addTab("Reports", panel8);
        final JSplitPane splitPane3 = new JSplitPane();
        splitPane3.setOrientation(0);
        panel8.add(splitPane3, BorderLayout.CENTER);
        final JScrollPane scrollPane3 = new JScrollPane();
        splitPane3.setLeftComponent(scrollPane3);
        reportsTable = new JTable();
        scrollPane3.setViewportView(reportsTable);
        reportPanel = new JPanel();
        reportPanel.setLayout(new BorderLayout(0, 0));
        splitPane3.setRightComponent(reportPanel);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootPanel;
    }
}
