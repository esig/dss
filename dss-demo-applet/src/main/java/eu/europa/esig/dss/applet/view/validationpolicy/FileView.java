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

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JRadioButton;

import com.jgoodies.binding.value.ValueHolder;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import eu.europa.esig.dss.applet.model.ValidationPolicyModel;
import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.ComponentFactory;
import eu.europa.esig.dss.applet.util.ResourceUtils;
import eu.europa.esig.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;

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
public class FileView extends WizardView<ValidationPolicyModel, ValidationPolicyWizardController> {

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
            final JFileChooser chooser = new JFileChooser();
            final int result = chooser.showOpenDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setSelectedFile(chooser.getSelectedFile());
            }
        }
    }

    private static final String I18N_EDIT_DEFAULT_POLICY = ResourceUtils.getI18n("EDIT_DEFAULT_POLICY");
    private static final String I18N_CHOOSE_FILE_POLICY = ResourceUtils.getI18n("CHOOSE_FILE_POLICY");
    private static final String I18N_NO_FILE_SELECTED = ResourceUtils.getI18n("NO_FILE_SELECTED");
    private static final String I18N_BROWSE_VALIDATION_POLICY = ResourceUtils.getI18n("BROWSE_VALIDATION_POLICY");
    private static final String I18N_FILE_TO_EDIT = ResourceUtils.getI18n("FILE_TO_EDIT");

    private final JLabel fileSourceLabel;
    private final JButton selectFileSource;
    private final JRadioButton editDefaultPolicy;
    private final JRadioButton chooseFilePolicy;
    private final ValueHolder defaultOrFileEditValidationPolicy;


    /**
     *
     * The default constructor for FileView.
     *
     * @param core
     * @param controller
     * @param model
     */
    public FileView(final AppletCore core, final ValidationPolicyWizardController controller, final ValidationPolicyModel model) {
        super(core, controller, model);
        fileSourceLabel = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        selectFileSource = ComponentFactory.createFileChooser(I18N_BROWSE_VALIDATION_POLICY, true, new SelectFileAEventListener());
        selectFileSource.setEnabled(!getModel().isEditDefaultPolicy());

        defaultOrFileEditValidationPolicy = new ValueHolder(true);
        editDefaultPolicy = ComponentFactory.createRadioButton(I18N_EDIT_DEFAULT_POLICY, defaultOrFileEditValidationPolicy, true);
        chooseFilePolicy = ComponentFactory.createRadioButton(I18N_CHOOSE_FILE_POLICY, defaultOrFileEditValidationPolicy, false);

        defaultOrFileEditValidationPolicy.addPropertyChangeListener(new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                getModel().setEditDefaultPolicy(
                      (Boolean) evt.getNewValue());

            }

        });
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    public void doInit() {
        final File selectedFile = getModel().getSelectedFile();
        fileSourceLabel.setText(selectedFile != null ? selectedFile.getName() : I18N_NO_FILE_SELECTED);
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {
        final FormLayout layout = new FormLayout("5dlu, pref, 5dlu, pref, 5dlu ,pref:grow ,5dlu", "5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();

        builder.add(editDefaultPolicy, cc.xyw(2, 2, 5));
        builder.add(chooseFilePolicy, cc.xyw(2, 4, 5));

        int columnOffset = 4;
        builder.addSeparator(I18N_FILE_TO_EDIT, cc.xyw(2, columnOffset+2, 5));
        builder.add(selectFileSource, cc.xy(2, columnOffset+4));
        builder.add(fileSourceLabel, cc.xyw(4, columnOffset+4, 3));
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

        if (evt.getPropertyName().equals(ValidationPolicyModel.PROPERTY_SELECTED_FILE)) {
            final File selectedFile = getModel().getSelectedFile();
            final String text = selectedFile == null ? I18N_NO_FILE_SELECTED : selectedFile.getName();
            fileSourceLabel.setText(text);
        }

        if (evt.getPropertyName().equals(ValidationPolicyModel.PROPERTY_EDIT_DEAFULT_POLICY)) {
            selectFileSource.setEnabled(!getModel().isEditDefaultPolicy());
        }
    }

}
