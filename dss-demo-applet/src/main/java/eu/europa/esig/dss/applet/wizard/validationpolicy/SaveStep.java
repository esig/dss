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
package eu.europa.esig.dss.applet.wizard.validationpolicy;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;

import eu.europa.esig.dss.applet.model.ValidationPolicyModel;
import eu.europa.esig.dss.applet.swing.mvc.ControllerException;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.ValidationPolicyDao;
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
 */public class SaveStep extends WizardStep<ValidationPolicyModel, ValidationPolicyWizardController> {
    /**
     * The default constructor for DSSWizardStep.
     *
     * @param model
     * @param view
     * @param controller
     */
    public SaveStep(ValidationPolicyModel model, WizardView<ValidationPolicyModel, ValidationPolicyWizardController> view, ValidationPolicyWizardController controller) {
        super(model, view, controller);
    }

    @Override
    protected void finish() throws ControllerException {
        final ValidationPolicy validationPolicy = getModel().getValidationPolicy();
        try {
            final FileOutputStream fileOutputStream = new FileOutputStream(getModel().getTargetFile());
            ValidationPolicyDao validationPolicyDao = new ValidationPolicyDao();
            validationPolicyDao.save(validationPolicy, fileOutputStream);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Class<? extends WizardStep<ValidationPolicyModel, ValidationPolicyWizardController>> getBackStep() {
        return EditStep.class;
    }

    @Override
    protected Class<? extends WizardStep<ValidationPolicyModel, ValidationPolicyWizardController>> getNextStep() {
        return FinishStep.class;
    }

    @Override
    protected int getStepProgression() {
        return 3;
    }

    @Override
    protected void init() throws ControllerException {
        if (getModel().getTargetFile() == null && getModel().getSelectedFile() != null) {
            getModel().setTargetFile(getModel().getSelectedFile());
        }
    }

    @Override
    protected boolean isValid() {
        return getModel().getTargetFile() != null;
    }
}
