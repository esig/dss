/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.applet.view.validation;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.SwingConstants;
import javax.swing.tree.DefaultTreeModel;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xhtmlrenderer.pdf.ITextRenderer;
import org.xhtmlrenderer.simple.FSScrollPane;
import org.xhtmlrenderer.simple.XHTMLPanel;

import com.jgoodies.binding.value.ValueHolder;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.lowagie.text.DocumentException;

import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.applet.component.model.XMLTreeModel;
import eu.europa.esig.dss.applet.model.ValidationModel;
import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.ComponentFactory;
import eu.europa.esig.dss.applet.wizard.validation.ValidationWizardController;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class ReportView extends WizardView<ValidationModel, ValidationWizardController> {

    private static final boolean DISPLAY_PLAINTEXT_REPORTS = false;
    private JTextArea detailedReportText;
    private JTextArea simpleReportText;
    private JTextArea diagnosticText;

    private JTree diagnostic;

    private final ValueHolder simpleReportValueHolder;
    private final ValueHolder detailedReportValueHolder;
    private final ValueHolder diagnosticValueHolder;

    private final XHTMLPanel simpleReportHtmlPanel;
    private final FSScrollPane simpleReportScrollPane;

    private final XHTMLPanel detailedReportHtmlPanel;
    private final FSScrollPane detailedReportScrollPane;

    /**
     * The default constructor for ReportView.
     *
     * @param core
     * @param controller
     * @param model
     */
    public ReportView(final AppletCore core, final ValidationWizardController controller, final ValidationModel model) {
        super(core, controller, model);
        detailedReportValueHolder = new ValueHolder("");
        diagnosticValueHolder = new ValueHolder("");
        simpleReportValueHolder = new ValueHolder("");

        if (DISPLAY_PLAINTEXT_REPORTS) {
            detailedReportText = ComponentFactory.createTextArea(detailedReportValueHolder);
            detailedReportText.setTabSize(2);
            simpleReportText = ComponentFactory.createTextArea(simpleReportValueHolder);
            simpleReportText.setTabSize(2);
            diagnosticText = ComponentFactory.createTextArea(diagnosticValueHolder);
            diagnosticText.setTabSize(2);
        }

        diagnostic = ComponentFactory.tree("Diagnostic", new DefaultTreeModel(null));

        simpleReportHtmlPanel = new XHTMLPanel();
        simpleReportScrollPane = new FSScrollPane(simpleReportHtmlPanel);

        detailedReportHtmlPanel = new XHTMLPanel();
        detailedReportScrollPane = new FSScrollPane(detailedReportHtmlPanel);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doInit()
     */

    @SuppressWarnings("unchecked")
    @Override
    public void doInit() {
        final ValidationModel model = getModel();

        final XmlDom simpleReport = model.getSimpleReport();
        final String simpleReportText = simpleReport.toString();
        simpleReportValueHolder.setValue(simpleReportText);

        final XmlDom detailedReport = model.getDetailedReport();
        final String reportText = detailedReport.toString();
        detailedReportValueHolder.setValue(reportText);

        final XMLTreeModel xmlTreeModelReport = new XMLTreeModel();
        Element doc = detailedReport.getRootElement();
        xmlTreeModelReport.setDocument(doc);

        final XmlDom diagnosticData = model.getDiagnosticData();
        final Document document = diagnosticData.getRootElement().getOwnerDocument();
        final XMLTreeModel xmlTreeModelDiagnostic = new XMLTreeModel();
        xmlTreeModelDiagnostic.setDocument(document.getDocumentElement());
        diagnostic = ComponentFactory.tree("Diagnostic", xmlTreeModelDiagnostic);
        expandTree(diagnostic);

        diagnosticValueHolder.setValue(diagnosticData.toString());

        final Document simpleReportHtml = getController().renderSimpleReportAsHtml();
        simpleReportHtmlPanel.setDocument(simpleReportHtml);

        final Document detailedReportHtml = getController().renderValidationReportAsHtml();
        detailedReportHtmlPanel.setDocument(detailedReportHtml);
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {

        JTabbedPane tabbedPane = new JTabbedPane(SwingConstants.TOP);
        tabbedPane.addTab("Simple Report", getHtmlPanel("Simple Report", simpleReportScrollPane, simpleReportHtmlPanel));
        tabbedPane.addTab("Detailed Report", getHtmlPanel("Detailed Report", detailedReportScrollPane, detailedReportHtmlPanel));
        tabbedPane.addTab("Diagnostic Tree", getDiagnosticPanel());
        if (DISPLAY_PLAINTEXT_REPORTS) {
            tabbedPane.addTab("Simple Report XML", getSimpleReportText());
            tabbedPane.addTab("Detailed Report XML", getDetailedReportText());
            tabbedPane.addTab("Diagnostic XML", getDiagnosticPanelText());
        }

        return tabbedPane;

    }

    private JPanel getHtmlPanel(final String textWithMnemonic, final FSScrollPane simpleReportScrollPane, final XHTMLPanel htmlPanel) {
        final String[] columnSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu"};
        final String[] rowSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu", "pref", "5dlu"};
        final PanelBuilder builder = ComponentFactory.createBuilder(columnSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator(textWithMnemonic, cc.xyw(2, 2, 3));
        builder.add(ComponentFactory.createScrollPane(simpleReportScrollPane), cc.xyw(2, 4, 3));
        builder.add(ComponentFactory.createSaveButton("Save as PDF", true, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                final JFileChooser fileChooser = new JFileChooser();
                int returnValue = fileChooser.showSaveDialog(simpleReportScrollPane);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    try {
                        OutputStream os = new FileOutputStream(fileChooser.getSelectedFile());
                        ITextRenderer renderer = new ITextRenderer();
                        renderer.setDocument(htmlPanel.getDocument(), "file:///");
                        renderer.layout();
                        renderer.createPDF(os);

                        os.close();
                    } catch (FileNotFoundException e) {
                        throw new RuntimeException(e);
                    } catch (DocumentException e) {
                        throw new RuntimeException(e);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                }
            }
        }), cc.xyw(2, 6, 1));

        return ComponentFactory.createPanel(builder);
    }

    private JPanel getSimpleReportText() {
        final String[] columnSpecs = new String[]{"5dlu", "fill:default:grow", "5dlu"};
        final String[] rowSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu"};
        final PanelBuilder builder = ComponentFactory.createBuilder(columnSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator("Detailed Report XML", cc.xyw(2, 2, 1));
        builder.add(ComponentFactory.createScrollPane(simpleReportText), cc.xyw(2, 4, 1));

        return ComponentFactory.createPanel(builder);
    }

    private JPanel getDetailedReportText() {
        final String[] columnSpecs = new String[]{"5dlu", "fill:default:grow", "5dlu"};
        final String[] rowSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu"};
        final PanelBuilder builder = ComponentFactory.createBuilder(columnSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator("Detailed Report XML", cc.xyw(2, 2, 1));
        builder.add(ComponentFactory.createScrollPane(detailedReportText), cc.xyw(2, 4, 1));

        return ComponentFactory.createPanel(builder);
    }

    private JPanel getDiagnosticPanel() {
        final String[] columnSpecs = new String[]{"5dlu", "fill:default:grow", "5dlu"};
        final String[] rowSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu"};
        final PanelBuilder builder = ComponentFactory.createBuilder(columnSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator("Diagnostic Tree", cc.xyw(2, 2, 1));
        builder.add(ComponentFactory.createScrollPane(diagnostic), cc.xyw(2, 4, 1));

        return ComponentFactory.createPanel(builder);
    }

    private JPanel getDiagnosticPanelText() {
        final String[] columnSpecs = new String[]{"5dlu", "fill:default:grow", "5dlu"};
        final String[] rowSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu"};
        final PanelBuilder builder = ComponentFactory.createBuilder(columnSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator("Diagnostic XML", cc.xyw(2, 2, 1));
        builder.add(ComponentFactory.createScrollPane(diagnosticText), cc.xyw(2, 4, 1));

        return ComponentFactory.createPanel(builder);
    }

    /**
     * fully expand the tree
     *
     * @param tree
     */
    private void expandTree(JTree tree) {
        // expand all
//        for (int i = 0; i < tree.getRowCount(); i++) {
        int i = 0;
        tree.expandRow(i);
//        }
    }

}
