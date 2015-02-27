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

package eu.europa.ec.markt.dss.applet.wizard.signature;

import java.io.File;

import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.applet.util.MOCCAAdapter;
import eu.europa.ec.markt.dss.common.PinInputDialog;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.ControllerException;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.token.MSCAPISignatureToken;
import eu.europa.ec.markt.dss.signature.token.Pkcs11SignatureToken;
import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class CertificateStep extends WizardStep<SignatureModel, SignatureWizardController> {
    /**
     * The default constructor for CertificateStep.
     *
     * @param model
     * @param view
     * @param controller
     */
    public CertificateStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view,
                           final SignatureWizardController controller) {
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
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getBackStep() {
        return SignatureDigestAlgorithmStep.class;
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {
        return PersonalDataStep.class;
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getStepProgression()
     */
    @Override
    protected int getStepProgression() {
        return 4;
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
     */
    @Override
    protected void init() throws ControllerException {
        final SignatureModel model = getModel();

        SignatureTokenConnection tokenConnetion = null;

        switch (model.getTokenType()) {

            case MSCAPI: {
                tokenConnetion = new MSCAPISignatureToken();
                break;
            }
            case MOCCA: {
                tokenConnetion = new MOCCAAdapter().createSignatureToken(new PinInputDialog(getController().getCore()));
                break;
            }
            case PKCS11:

                final File file = model.getPkcs11File();

                tokenConnetion = new Pkcs11SignatureToken(file.getAbsolutePath(), model.getPkcs11Password().toCharArray());

                break;
            case PKCS12:
                tokenConnetion = new Pkcs12SignatureToken(model.getPkcs12Password(), model.getPkcs12File());
                break;
            default:
                throw new RuntimeException("No token connection selected");
        }
        try {
            model.setTokenConnection(tokenConnetion);
            model.setPrivateKeys(tokenConnetion.getKeys());
        } catch (final DSSException e) {
            throw new ControllerException(e);
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {
        return getModel().getSelectedPrivateKey() != null;
    }

}
