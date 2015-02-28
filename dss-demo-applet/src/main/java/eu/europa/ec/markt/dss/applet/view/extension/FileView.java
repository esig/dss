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
package eu.europa.ec.markt.dss.applet.view.extension;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;

import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import eu.europa.ec.markt.dss.applet.model.ExtendSignatureModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.extension.ExtensionWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

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
public class FileView extends WizardView<ExtendSignatureModel, ExtensionWizardController> {
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
    private final class ClearEventListener implements ActionListener {
        /*
         * (non-Javadoc)
         * 
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {
            getModel().setOriginalFile(null);
            getModel().setSelectedFile(null);
        }

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
    private final class SelectFileAEventListener implements ActionListener {
        /*
         * (non-Javadoc)
         * 
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {
            final JFileChooser chooser = new JFileChooser();
            final int result = chooser.showOpenDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setSelectedFile(chooser.getSelectedFile());
            }
        }

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
    private final class SelectFileBEventListener implements ActionListener {
        /*
         * (non-Javadoc)
         * 
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {
            final JFileChooser chooser = new JFileChooser();
            final int result = chooser.showOpenDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setOriginalFile(chooser.getSelectedFile());
            }
        }

    }

    private static final String I18N_NO_FILE_SELECTED = ResourceUtils.getI18n("NO_FILE_SELECTED");
    private static final String I18N_BROWSE = ResourceUtils.getI18n("BROWSE");
    private static final String I18N_FILE_TO_EXTEND = ResourceUtils.getI18n("SIGNED_FILE_TO_EXTEND");
    private static final String I18N_FILE_TO_EXTEND_DESCRIPTION = ResourceUtils.getI18n("WHEN_EXTENDING_DETACHED_TO_A_JAVA");

    private static final String I18N_FILE_ORIGINAL = "Original File";

    private final JLabel fileASourceLabel;
    private final JLabel fileBSourceLabel;
    private final JButton selectFileASource;
    private final JButton selectFileBSource;

    private final JButton clearButton;

    /**
     * 
     * The default constructor for FileView.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public FileView(final AppletCore core, final ExtensionWizardController controller, final ExtendSignatureModel model) {
        super(core, controller, model);
        fileASourceLabel = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        selectFileASource = ComponentFactory.createFileChooser(I18N_BROWSE, true, new SelectFileAEventListener());
        fileBSourceLabel = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        selectFileBSource = ComponentFactory.createFileChooser(I18N_BROWSE, true, new SelectFileBEventListener());
        clearButton = ComponentFactory.createClearButton(true, new ClearEventListener());
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {

        final FormLayout layout = new FormLayout("5dlu, pref, 5dlu, pref, 5dlu ,pref:grow ,5dlu", "5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();
        builder.addSeparator(I18N_FILE_TO_EXTEND, cc.xyw(2, 2, 5));
        builder.add(selectFileASource, cc.xy(2, 4));
        builder.add(fileASourceLabel, cc.xyw(4, 4, 3));
        builder.addSeparator(I18N_FILE_ORIGINAL, cc.xyw(2, 6, 5));
        builder.add(selectFileBSource, cc.xy(2, 8));
        builder.add(fileBSourceLabel, cc.xyw(4, 8, 3));
        builder.addLabel(I18N_FILE_TO_EXTEND_DESCRIPTION, cc.xyw(2, 10, 5));
        builder.add(clearButton, cc.xy(2, 12));
        return ComponentFactory.createPanel(builder);

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView#wizardModelChange(java.beans.PropertyChangeEvent
     * )
     */
    @Override
    public void wizardModelChange(final PropertyChangeEvent evt) {

        final String propertyName = evt.getPropertyName();

        if (propertyName.equals(ExtendSignatureModel.PROPERTY_SELECTED_FILE)) {
            final File selectedFile = getModel().getSelectedFile();
            final String text = selectedFile == null ? I18N_NO_FILE_SELECTED : selectedFile.getName();
            fileASourceLabel.setText(text);
        }

        if (propertyName.equals(ExtendSignatureModel.PROPERTY_ORIGINAL_FILE)) {
            final File originalFile = getModel().getOriginalFile();
            final String text = originalFile == null ? I18N_NO_FILE_SELECTED : originalFile.getName();
            fileBSourceLabel.setText(text);
        }
    }

}
