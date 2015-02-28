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
package eu.europa.ec.markt.dss.applet.wizard.validation;

import java.io.File;

import eu.europa.ec.markt.dss.applet.model.ValidationModel;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.ControllerException;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
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
public class FormStep extends WizardStep<ValidationModel, ValidationWizardController> {
    /**
     * The default constructor for FormStep.
     *
     * @param model
     * @param view
     * @param controller
     */
    public FormStep(final ValidationModel model, final WizardView<ValidationModel, ValidationWizardController> view, final ValidationWizardController controller) {
        super(model, view, controller);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#finish()
     */
    @Override
    protected void finish() throws ControllerException {

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getBackStep()
     */
    @Override
    protected Class<? extends WizardStep<ValidationModel, ValidationWizardController>> getBackStep() {
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<ValidationModel, ValidationWizardController>> getNextStep() {
        return ReportStep.class;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getStepProgression()
     */
    @Override
    protected int getStepProgression() {
        return 1;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
     */
    @Override
    protected void init() {
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {
        final File signedFile = getModel().getSignedFile();
        final File originalFile = getModel().getOriginalFile();
        final boolean validationLegacyChosen = getModel().isValidationLegacyChosen();
        final boolean defaultPolicy = getModel().isDefaultPolicy();
        final File selectedPolicyFile = getModel().getSelectedPolicyFile();


        boolean valid = signedFile != null && signedFile.exists() && signedFile.isFile();

        if (originalFile != null) {
            valid &= originalFile.exists() && originalFile.isFile();
        }

        if (!validationLegacyChosen) {
            if (!defaultPolicy) {
                valid &= selectedPolicyFile != null && selectedPolicyFile.exists() && selectedPolicyFile.isFile();
            }
        }

        return valid;
    }
}
