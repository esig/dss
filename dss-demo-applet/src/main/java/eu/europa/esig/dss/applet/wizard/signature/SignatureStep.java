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

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.applet.SignatureTokenType;
import eu.europa.esig.dss.applet.main.Parameters;
import eu.europa.esig.dss.applet.model.SignatureModel;
import eu.europa.esig.dss.applet.swing.mvc.ControllerException;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.wsclient.signature.SignaturePackaging;

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
public class SignatureStep extends WizardStep<SignatureModel, SignatureWizardController> {
	/**
	 *
	 * The default constructor for SignatureStep.
	 *
	 * @param model
	 * @param view
	 * @param controller
	 */
	public SignatureStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view, final SignatureWizardController controller) {
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
		return FileStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getNextStep()
	 */
	@Override
	protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {

		final Parameters parameters = getController().getParameter();
		if (parameters.hasSignatureTokenType()) {
			final SignatureTokenType tokenType = parameters.getSignatureTokenType();
			getModel().setTokenType(tokenType);
			switch (tokenType) {
				case MOCCA:
					return FinishStep.class;
				case MSCAPI:
					return CertificateStep.class;
				case PKCS11:
					return PKCS11Step.class;
				case PKCS12:
					return PKCS12Step.class;
				default:
					throw new RuntimeException("Cannot evaluate token type");
			}

		} else {
			return TokenStep.class;
		}

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getStepProgression()
	 */
	@Override
	protected int getStepProgression() {
		return 2;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#execute()
	 */
	@Override
	protected void init() {

		final SignatureModel model = getModel();
		final Parameters parameters = getController().getParameter();
		final SignaturePackaging packaging = parameters.getSignaturePackaging();
		final String level = parameters.getSignatureLevel();
		final String format = parameters.getSignatureFormat();

		if (format != null) {
			model.setFormat(format);
			if (packaging != null) {
				model.setPackaging(packaging);
				if (StringUtils.isNotEmpty(level)) {
					model.setLevel(level);
				}
			}
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#isValid()
	 */
	@Override
	protected boolean isValid() {
		final SignatureModel model = getModel();
		return StringUtils.isNotEmpty(model.getFormat()) && (model.getPackaging() != null) && StringUtils.isNotEmpty(model.getLevel());
	}

}
