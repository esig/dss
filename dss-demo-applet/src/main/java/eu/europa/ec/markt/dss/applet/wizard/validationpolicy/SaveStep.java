/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.applet.wizard.validationpolicy;

import eu.europa.ec.markt.dss.applet.model.ValidationPolicyModel;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.ControllerException;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint.ValidationPolicy;
import eu.europa.ec.markt.dss.applet.util.ValidationPolicyDao;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;

/**
 *
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
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
