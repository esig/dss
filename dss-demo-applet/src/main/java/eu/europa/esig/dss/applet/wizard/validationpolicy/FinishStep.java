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

import eu.europa.esig.dss.applet.model.ValidationPolicyModel;
import eu.europa.esig.dss.applet.swing.mvc.ControllerException;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;

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
public class FinishStep extends WizardStep<ValidationPolicyModel, ValidationPolicyWizardController> {
    /**
     * The default constructor for FinishStep.
     *
     * @param model
     * @param view
     * @param controller
     */
    public FinishStep(ValidationPolicyModel model, WizardView<ValidationPolicyModel, ValidationPolicyWizardController> view, ValidationPolicyWizardController controller) {
        super(model, view, controller);
    }

    @Override
    protected void finish() throws ControllerException {
    }

    @Override
    protected Class<? extends WizardStep<ValidationPolicyModel, ValidationPolicyWizardController>> getBackStep() {
        return SaveStep.class;
    }

    @Override
    protected Class<? extends WizardStep<ValidationPolicyModel, ValidationPolicyWizardController>> getNextStep() {
        return null;
    }

    @Override
    protected int getStepProgression() {
        return 4;
    }

    @Override
    protected void init() throws ControllerException {
    }

    @Override
    protected boolean isValid() {
        return true;
    }
}
