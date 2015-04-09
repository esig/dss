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

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.applet.model.ValidationPolicyModel;
import eu.europa.esig.dss.applet.swing.mvc.ControllerException;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.ValidationPolicyDao;
import eu.europa.esig.dss.validation.model.ValidationPolicy;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class FileStep extends WizardStep<ValidationPolicyModel, ValidationPolicyWizardController> {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(FileStep.class.getSimpleName());

    /**
     * The default constructor for FileStep.
     *
     * @param model
     * @param view
     * @param controller
     */
    public FileStep(ValidationPolicyModel model, WizardView<ValidationPolicyModel, ValidationPolicyWizardController> view,
                    ValidationPolicyWizardController controller) {
        super(model, view, controller);
    }

    @Override
    protected void finish() throws ControllerException {
        URL validationPolicyURL = getController().getCore().getParameters().getDefaultPolicyUrl();
        URL validationXsdPolicyURL = getController().getCore().getParameters().getDefaultXsdPolicyUrl();
        if (!getModel().isEditDefaultPolicy()) {
            // load specified validation policy file
            try {
                final File selectedFile = getModel().getSelectedFile();
                if (selectedFile.exists()) {
                    validationPolicyURL = selectedFile.toURI().toURL();
                } else {
                    throw new DSSException(selectedFile.getAbsolutePath() + " not found");
                }
            } catch (MalformedURLException e) {
                throw new DSSException(e);
            }
        }

        final ValidationPolicyDao validationPolicyDao = new ValidationPolicyDao();
        ValidationPolicy validationPolicy = validationPolicyDao.load(validationPolicyURL, validationXsdPolicyURL);

        getModel().setValidationPolicy(validationPolicy);

    }

    @Override
    protected Class<? extends WizardStep<ValidationPolicyModel, ValidationPolicyWizardController>> getBackStep() {
        return null;
    }

    @Override
    protected Class<? extends WizardStep<ValidationPolicyModel, ValidationPolicyWizardController>> getNextStep() {
        return EditStep.class;
    }

    @Override
    protected int getStepProgression() {
        return 1;
    }

    @Override
    protected void init() throws ControllerException {
    }

    @Override
    protected boolean isValid() {
        final ValidationPolicyModel model = getModel();
        final File selectedFile = model.getSelectedFile();
        final boolean editDefaultPolicy = model.isEditDefaultPolicy();
        boolean valid = true;
        if (!editDefaultPolicy) {
            valid = selectedFile != null && selectedFile.exists() && selectedFile.isFile();
        }
        return valid;
    }
}
