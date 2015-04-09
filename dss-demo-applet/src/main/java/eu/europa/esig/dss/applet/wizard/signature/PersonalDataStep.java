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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

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
public class PersonalDataStep extends WizardStep<SignatureModel, SignatureWizardController> {
	/**
	 *
	 * The default constructor for PersonalDataStep.
	 *
	 * @param model
	 * @param view
	 * @param controller
	 */
	public PersonalDataStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view, final SignatureWizardController controller) {
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
		return CertificateStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getNextStep()
	 */
	@Override
	protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {
		return SaveStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getStepProgression()
	 */
	@Override
	protected int getStepProgression() {
		return 5;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#execute()
	 */
	@Override
	protected void init() {

		final Parameters parameters = getController().getParameter();
		final SignatureModel model = getModel();

		if (parameters.hasSignaturePolicyAlgo() && StringUtils.isEmpty(model.getSignaturePolicyAlgo())) {
			model.setSignaturePolicyAlgo(parameters.getSignaturePolicyAlgo());
		}

		if (parameters.hasSignaturePolicyValue() && StringUtils.isEmpty(model.getSignaturePolicyValue())) {
			model.setSignaturePolicyValue(Base64.encodeBase64String(parameters.getSignaturePolicyValue()));
		}

		// TODO: (Bob: 2014 Jan 19) To be adapted to baseline profile
		final boolean levelBES = model.getLevel().toUpperCase().endsWith("-BES");
		model.setSignaturePolicyVisible(!levelBES);

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#isValid()
	 */
	@Override
	protected boolean isValid() {

		final SignatureModel model = getModel();

		if (model.isSignaturePolicyCheck()) {
			return StringUtils.isNotEmpty(model.getSignaturePolicyAlgo()) && StringUtils.isNotEmpty(model.getSignaturePolicyId()) && StringUtils.isNotEmpty(model.getSignaturePolicyValue());
		}
		return true;
	}
}
