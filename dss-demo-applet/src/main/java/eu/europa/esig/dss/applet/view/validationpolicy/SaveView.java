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
package eu.europa.esig.dss.applet.view.validationpolicy;

import java.awt.Color;
import java.awt.Container;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import eu.europa.esig.dss.applet.model.ValidationPolicyModel;
import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.ComponentFactory;
import eu.europa.esig.dss.applet.util.ResourceUtils;
import eu.europa.esig.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;
import eu.europa.esig.dss.validation.model.ValidationPolicy;

/**
 *
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class SaveView extends WizardView<ValidationPolicyModel, ValidationPolicyWizardController> {

    private static final String I18N_SAVE_TO_FILE = ResourceUtils.getI18n("SAVE_TO_FILE");
    private static final String I18N_NO_FILE_SELECTED = ResourceUtils.getI18n("NO_FILE_SELECTED");
    private static final String I18N_BROWSE = ResourceUtils.getI18n("BROWSE");


    private final JTextArea validationArea;
    private final JLabel fileTargetLabel;
    private final JButton selectFileTarget;
    private final JScrollPane scrollPane;


    /**
     * The default constructor for SaveView.
     *
     * @param core
     * @param controller
     * @param model
     */
    public SaveView(AppletCore core, ValidationPolicyWizardController controller, ValidationPolicyModel model) {
        super(core, controller, model);

        validationArea = new JTextArea();
        validationArea.setColumns(10);
        validationArea.setRows(10);
        scrollPane = new JScrollPane(validationArea);
        validationArea.setForeground(Color.ORANGE);
        validationArea.setFont(new Font(validationArea.getFont().getName(), Font.BOLD, validationArea.getFont().getSize()));
        validationArea.setEditable(false);
        fileTargetLabel = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        selectFileTarget = ComponentFactory.createFileChooser(I18N_BROWSE, true, new SelectFileAEventListener());
    }

    /**
     *
     * TODO
     *
     *
     *
     *
     *
     *
     */
    private class SelectFileAEventListener implements ActionListener {
        /*
         * (non-Javadoc)
         *
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {
            final JFileChooser chooser = new JFileChooser() {
                @Override
                public void approveSelection() {
                    final File f = getSelectedFile();
                    if (f.exists() && getDialogType() == SAVE_DIALOG) {
                        int result = JOptionPane.showConfirmDialog(this, "The file exists, overwrite?", "Existing file", JOptionPane.YES_NO_CANCEL_OPTION);
                        switch (result) {
                            case JOptionPane.YES_OPTION:
                                super.approveSelection();
                                return;
                            case JOptionPane.NO_OPTION:
                                return;
                            case JOptionPane.CLOSED_OPTION:
                                return;
                            case JOptionPane.CANCEL_OPTION:
                                cancelSelection();
                                return;
                        }
                    }
                    super.approveSelection();
                }
            };
            if (getModel().getTargetFile() != null){
                chooser.setSelectedFile(getModel().getTargetFile());
            }
            final int result = chooser.showSaveDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setTargetFile(chooser.getSelectedFile());
            }
        }
    }



    /*
     * (non-Javadoc)
     *
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    public void doInit() {
        final File targetFile = getModel().getTargetFile();
        fileTargetLabel.setText(targetFile != null ? targetFile.getName() : I18N_NO_FILE_SELECTED);
        SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema") ;

        String validationErrors = "";
        final ValidationPolicy validationPolicy = getModel().getValidationPolicy();
        Document document = validationPolicy.getDocument();
        try {
            InputStream stream = validationPolicy.getSourceXSD().openStream();
            InputSource sourceentree = new InputSource(stream);
            SAXSource sourceXsd = new SAXSource(sourceentree);

            Schema schema = factory.newSchema(sourceXsd);
            Validator validator = schema.newValidator() ;
            Source input = new DOMSource(document);
            validator.validate(input);
        } catch (SAXException e) {
            validationErrors = e.getMessage();
        } catch (IOException e) {
            validationErrors = e.getMessage();
        }
        validationArea.setText(validationErrors);
        scrollPane.setVisible(!validationErrors.equals(""));
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {
        final FormLayout layout = new FormLayout("5dlu, pref, 5dlu, pref, 5dlu ,pref:grow ,5dlu, fill:default:grow, 5dlu", "5dlu, pref, 5dlu, pref, 5dlu, fill:default:grow, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator(I18N_SAVE_TO_FILE, cc.xyw(2, 2, 5));
        builder.add(selectFileTarget, cc.xy(2, 4));
        builder.add(fileTargetLabel, cc.xyw(4, 4, 3));
        builder.add(scrollPane, cc.xywh(2,5,8,3));
        return ComponentFactory.createPanel(builder);
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView#wizardModelChange(java.beans.PropertyChangeEvent
     * )
     */
    @Override
    public void wizardModelChange(final PropertyChangeEvent evt) {

        if (evt.getPropertyName().equals(ValidationPolicyModel.PROPERTY_TARGET_FILE)) {
            final File targetFile = getModel().getTargetFile();
            final String text = targetFile == null ? I18N_NO_FILE_SELECTED : targetFile.getName();
            fileTargetLabel.setText(text);
        }

    }
}
