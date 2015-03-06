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
package eu.europa.ec.markt.dss.applet.view.validation;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JRadioButton;

import com.jgoodies.binding.PresentationModel;
import com.jgoodies.binding.value.AbstractValueModel;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import eu.europa.ec.markt.dss.applet.model.ValidationModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.validation.ValidationWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class ValidationView extends WizardView<ValidationModel, ValidationWizardController> {

    private static final boolean DISPLAY_LEGACY_VALIDATION = false;

    /**
     * TODO
     *
     *
     *
     *
     *
     *
     */
    private class ClearEventListener implements ActionListener {
        /*
         * (non-Javadoc)
         * 
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {
            final ValidationModel model = getModel();
            model.setOriginalFile(null);
            model.setSignedFile(null);
        }
    }

    /**
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

            final JFileChooser chooser = new JFileChooser(getModel().getSignedFile());
            final int result = chooser.showOpenDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setSignedFile(chooser.getSelectedFile());
            }
        }
    }
  /**
     * TODO
     *
     *
     *
     *
     *
     *
     */
    private class SelectPolicyFileEventListener implements ActionListener {
        /*
         * (non-Javadoc)
         *
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {

            final JFileChooser chooser = new JFileChooser(getModel().getSelectedPolicyFile());
            final int result = chooser.showOpenDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setSelectedPolicyFile(chooser.getSelectedFile());
            }
        }
    }

    /**
     * TODO
     *
     *
     *
     *
     *
     *
     */
    private class SelectFileBEventListener implements ActionListener {
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
    private static final String I18N_BROWSE_SIGNED = ResourceUtils.getI18n("BROWSE_SIGNED");
    private static final String I18N_BROWSE_ORIGINAL = ResourceUtils.getI18n("BROWSE_ORIGINAL");
    private static final String I18N_SIGNED_FILE_TO_VALIDATE = ResourceUtils.getI18n("SIGNED_FILE_TO_VALIDATE");
    private static final String I18N_ORIGINAL_FILE = ResourceUtils.getI18n("ORIGINAL_FILE") + " " + ResourceUtils.getI18n("ONLY_IF_DETACHEDJAVA");
    private static final String I18_VALIDATION_LEGACY = ResourceUtils.getI18n("VALIDATION_LEGACY");
    private static final String I18_VALIDATION_102853 = ResourceUtils.getI18n("VALIDATION_102853");
    private static final String I18N_VALIDATION_TYPE = ResourceUtils.getI18n("VALIDATION_TYPE");
    private static final String I18N_VALIDATION_102853_TYPE = ResourceUtils.getI18n("VALIDATION_102853_TYPE");

    private static final String I18N_DEFAULT_VALIDATION_102853 = ResourceUtils.getI18n("DEFAULT_VALIDATION_102853");
    private static final String I18N_CUSTOM_VALIDATION_102853 = ResourceUtils.getI18n("CUSTOM_VALIDATION_102853");
    private static final String I18N_BROWSE_VALIDATION_POLICY = ResourceUtils.getI18n("BROWSE_VALIDATION_POLICY");


    private final JLabel fileB;

    private final JLabel fileA;

    private final JButton selectFileA;

    private final JButton selectFileB;
    private final JButton clear;

    private final JRadioButton validationLegacy;
    private final JRadioButton validation102853;

    private JComponent validationTypeSeparator;

    private final JRadioButton defaultValidation;
    private final JRadioButton customValidation;

    private final JLabel filePolicyLabel;
    private final JButton selectFilePolicy;

    /**
     * The default constructor for ValidationView.
     *
     * @param core
     * @param controller
     * @param model
     */
    public ValidationView(final AppletCore core, final ValidationWizardController controller, final ValidationModel model) {
        super(core, controller, model);

        selectFileA = ComponentFactory.createFileChooser(I18N_BROWSE_SIGNED, true, new SelectFileAEventListener());
        selectFileA.setName("fileA");
        selectFileB = ComponentFactory.createFileChooser(I18N_BROWSE_ORIGINAL, true, new SelectFileBEventListener());
        selectFileB.setName("fileB");
        clear = ComponentFactory.createClearButton(true, new ClearEventListener());
        clear.setName("clear");
        fileA = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        fileB = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);

        PresentationModel<ValidationModel> presentationModel = new PresentationModel<ValidationModel>(getModel());
        AbstractValueModel validationLegacyChosen = presentationModel.getModel(getModel().CHANGE_PROPERTY_VALIDATION_LEGACY_CHOSEN);

        validationLegacy = ComponentFactory.createRadioButton(I18_VALIDATION_LEGACY, validationLegacyChosen, Boolean.TRUE);
        validationLegacy.setName("validationLegacy");
        validation102853 = ComponentFactory.createRadioButton(I18_VALIDATION_102853, validationLegacyChosen, Boolean.FALSE);
        validation102853.setName("validation");

        AbstractValueModel validationDefaultChosen = presentationModel.getModel(getModel().CHANGE_PROPERTY_DEFAULT_POLICY);

        defaultValidation = ComponentFactory.createRadioButton(I18N_DEFAULT_VALIDATION_102853, validationDefaultChosen, Boolean.TRUE);
        defaultValidation.setName("defaultValidation");
        customValidation = ComponentFactory.createRadioButton(I18N_CUSTOM_VALIDATION_102853, validationDefaultChosen, Boolean.FALSE);
        customValidation.setName("customValidation");

        filePolicyLabel = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        selectFilePolicy = ComponentFactory.createFileChooser(I18N_BROWSE_VALIDATION_POLICY, true,
              new SelectPolicyFileEventListener());
        selectFilePolicy.setName("selectFilePolicy");
        activeOrDisableCustomFile();

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    public void doInit() {

        final ValidationModel model = getModel();
        fileA.setText(model.getSignedFile() != null ? model.getSignedFile().getName() : I18N_NO_FILE_SELECTED);
        fileB.setText(model.getOriginalFile() != null ? model.getOriginalFile().getName() : I18N_NO_FILE_SELECTED);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {
        final FormLayout layout = new FormLayout("5dlu, pref, 5dlu, pref, 5dlu, pref:grow, 5dlu", "5dlu, p, 5dlu, pref, 5dlu, p, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu");

        final CellConstraints cc = new CellConstraints();
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        int row = 2;
        builder.addSeparator(I18N_SIGNED_FILE_TO_VALIDATE, cc.xyw(2, 2, 6));
        builder.add(selectFileA, cc.xy(2, row=row+2));
        builder.add(fileA, cc.xyw(4, row, 4));
        builder.addSeparator(I18N_ORIGINAL_FILE, cc.xyw(2, row=row+2, 6));
        builder.add(selectFileB, cc.xy(2, row=row+2));
        builder.add(fileB, cc.xyw(4, row, 4));
        builder.add(clear, cc.xy(2, row=row+2));
        if (DISPLAY_LEGACY_VALIDATION) {
            builder.addSeparator(I18N_VALIDATION_TYPE, cc.xyw(2, row=row+2, 6));
            builder.add(validationLegacy, cc.xyw(2, row=row+2, 6));
            builder.add(validation102853, cc.xyw(2, row=row+2, 6));
        }

        validationTypeSeparator = builder.addSeparator(ValidationView.I18N_VALIDATION_102853_TYPE, cc.xyw(2, row=row+2, 6));
        builder.add(defaultValidation, cc.xyw(2, row=row+2, 6));
        builder.add(customValidation, cc.xyw(2, row=row+2, 6));
        builder.add(selectFilePolicy, cc.xy(2, row=row+2));
        builder.add(filePolicyLabel, cc.xyw(4, row, 3));

        displayOrHideValidation();


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
        final ValidationModel model = getModel();

        if (evt.getPropertyName().equals(ValidationModel.CHANGE_PROPERTY_ORIGINAL_FILE)) {

            if (model.getOriginalFile() == null) {
                fileB.setText(I18N_NO_FILE_SELECTED);
            } else {
                fileB.setText(model.getOriginalFile().getName());
            }
            return;
        }

        if (evt.getPropertyName().equals(ValidationModel.CHANGE_PROPERTY_SIGNED_FILE)) {

            if (model.getSignedFile() == null) {
                fileA.setText(I18N_NO_FILE_SELECTED);
            } else {
                fileA.setText(model.getSignedFile().getName());
            }
            return;
        }

        if (evt.getPropertyName().equals(ValidationModel.CHANGE_PROPERTY_SELECTED_POLICY_FILE)) {

            if (model.getSelectedPolicyFile() == null) {
                fileA.setText(I18N_NO_FILE_SELECTED);
            } else {
                filePolicyLabel.setText(model.getSelectedPolicyFile().getName());
            }
            return;
        }

        if (evt.getPropertyName().equals(ValidationModel.CHANGE_PROPERTY_VALIDATION_LEGACY_CHOSEN)) {
            displayOrHideValidation();
            return;
        }

        if (evt.getPropertyName().equals(ValidationModel.CHANGE_PROPERTY_DEFAULT_POLICY)) {
            activeOrDisableCustomFile();
            return;
        }

    }

    private void activeOrDisableCustomFile() {
        selectFilePolicy.setEnabled(!getModel().isDefaultPolicy());
    }

    private void displayOrHideValidation() {
        final ValidationModel model = getModel();
        final boolean validationLegacyChosen = model.isValidationLegacyChosen();
        final boolean visible = !validationLegacyChosen;
        validationTypeSeparator.setVisible(visible);
        defaultValidation.setVisible(visible);
        customValidation.setVisible(visible);
        selectFilePolicy.setVisible(visible);
        filePolicyLabel.setVisible(visible);
    }

}
