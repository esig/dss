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

import java.io.File;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.applet.PinInputDialog;
import eu.europa.esig.dss.applet.model.SignatureModel;
import eu.europa.esig.dss.applet.swing.mvc.ControllerException;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.MOCCAAdapter;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;

/**
 * TODO
 *
 *
 *
 *
 *
 *
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
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#finish()
	 */
	@Override
	protected void finish() throws ControllerException {

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getBackStep()
	 */
	@Override
	protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getBackStep() {
		return SignatureDigestAlgorithmStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getNextStep()
	 */
	@Override
	protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {
		return PersonalDataStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getStepProgression()
	 */
	@Override
	protected int getStepProgression() {
		return 4;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#execute()
	 */
	@Override
	protected void init() throws ControllerException {
		final SignatureModel model = getModel();

		SignatureTokenConnection tokenConnetion = null;

		switch (model.getTokenType()) {

			case MSCAPI: {
				tokenConnetion = new MSCAPISignatureToken(new PinInputDialog(getController().getCore()));
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
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#isValid()
	 */
	@Override
	protected boolean isValid() {
		return getModel().getSelectedPrivateKey() != null;
	}

}
