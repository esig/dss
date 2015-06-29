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
package eu.europa.esig.dss.applet.view.signature;

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

import eu.europa.esig.dss.applet.model.SignatureModel;
import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.ComponentFactory;
import eu.europa.esig.dss.applet.util.ResourceUtils;
import eu.europa.esig.dss.applet.wizard.signature.SignatureWizardController;

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
public class SaveView extends WizardView<SignatureModel, SignatureWizardController> {

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
    private class SelectTargetFileEventListener implements ActionListener {
        /*
         * (non-Javadoc)
         * 
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {
            final File targetFile = getModel().getTargetFile();
            final JFileChooser chooser = new JFileChooser();
            chooser.setCurrentDirectory(targetFile.getParentFile());
            chooser.setSelectedFile(targetFile);

            final int result = chooser.showSaveDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setTargetFile(chooser.getSelectedFile());
            }
        }
    }

    private static final String I18N_NO_FILE_SELECTED = ResourceUtils.getI18n("NO_FILE_SELECTED");
    private static final String I18N_CHOOSE_DESTINATION = ResourceUtils.getI18n("CHOOSE_DESTINATION");

    private final JLabel fileTargetLabel;
    private final JButton selectFileTarget;

    /**
     * 
     * The default constructor for SaveView.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public SaveView(final AppletCore core, final SignatureWizardController controller, final SignatureModel model) {
        super(core, controller, model);
        fileTargetLabel = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        selectFileTarget = ComponentFactory.createFileChooser(I18N_CHOOSE_DESTINATION, true, new SelectTargetFileEventListener());
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
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {
        final FormLayout layout = new FormLayout("5dlu, pref, 5dlu, pref, 5dlu ,pref:grow ,5dlu", "5dlu, pref, 5dlu, pref, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();
        builder.addSeparator(ResourceUtils.getI18n("CHOOSE_DESTINATION"), cc.xyw(2, 2, 5));
        builder.add(selectFileTarget, cc.xy(2, 4));
        builder.add(fileTargetLabel, cc.xyw(4, 4, 3));
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

        if (evt.getPropertyName().equals(SignatureModel.PROPERTY_TARGET_FILE)) {
            final SignatureModel model = getModel();
            final File targetFile = model.getTargetFile();
            final String text = targetFile == null ? I18N_NO_FILE_SELECTED : targetFile.getName();
            fileTargetLabel.setText(text);
        }
    }
}
