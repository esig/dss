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
package eu.europa.esig.dss.applet.wizard.signature;

import eu.europa.esig.dss.applet.SignatureTokenType;
import eu.europa.esig.dss.applet.main.Parameters;
import eu.europa.esig.dss.applet.model.SignatureModel;
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
public class SignatureDigestAlgorithmStep extends WizardStep<SignatureModel, SignatureWizardController> {
    /**
     * 
     * The default constructor for SignatureDigestAlgorithmStep.
     * 
     * @param model
     * @param view
     * @param controller
     */
    public SignatureDigestAlgorithmStep(SignatureModel model, WizardView<SignatureModel, SignatureWizardController> view, SignatureWizardController controller) {
        super(model, view, controller);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#finish()
     */
    @Override
    protected void finish() throws ControllerException {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getBackStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getBackStep() {
        final Parameters parameters = getController().getParameter();
        if (parameters.hasSignatureTokenType()) {
            return SignatureStep.class;
        } else {
            return TokenStep.class;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {
        final SignatureTokenType tokenType = getModel().getTokenType();

        if (tokenType == null) {
            return this.getClass();
        }

        switch (tokenType) {
            case MOCCA:
            case MSCAPI:
                return CertificateStep.class;
            case PKCS11:
                return PKCS11Step.class;
            case PKCS12:
                return PKCS12Step.class;
        }
        return this.getClass();

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getStepProgression()
     */
    @Override
    protected int getStepProgression() {
        return 3;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#init()
     */
    @Override
    protected void init() throws ControllerException {

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {
        return true;
    }

}
