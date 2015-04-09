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

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.applet.model.SignatureModel;
import eu.europa.esig.dss.applet.swing.mvc.ControllerException;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.wsclient.signature.SignaturePackaging;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class SaveStep extends WizardStep<SignatureModel, SignatureWizardController> {
	/**
	 * The default constructor for SaveStep.
	 *
	 * @param model
	 * @param view
	 * @param controller
	 */
	public SaveStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view, final SignatureWizardController controller) {
		super(model, view, controller);
	}

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
		return PersonalDataStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getNextStep()
	 */
	@Override
	protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {
		return FinishStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getStepProgression()
	 */
	@Override
	protected int getStepProgression() {
		return 6;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#execute()
	 */
	@Override
	protected void init() {

		final File selectedFile = getModel().getSelectedFile();
		// Initialize the target file base on the current selected file

		final SignaturePackaging signaturePackaging = getModel().getPackaging();
		final String signatureLevel = getModel().getLevel();
		final File targetFile = prepareTargetFileName(selectedFile, signaturePackaging, signatureLevel);

		getModel().setTargetFile(targetFile);

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#isValid()
	 */
	@Override
	protected boolean isValid() {
		final File targetFile = getModel().getTargetFile();
		return targetFile != null;
	}

	private File prepareTargetFileName(final File file, final SignaturePackaging signaturePackaging, final String signatureLevel) {

		final File parentDir = file.getParentFile();
		final String originalName = StringUtils.substringBeforeLast(file.getName(), ".");
		final String originalExtension = "." + StringUtils.substringAfterLast(file.getName(), ".");
		final String level = signatureLevel.toUpperCase();

		if (((SignaturePackaging.ENVELOPING == signaturePackaging) || (SignaturePackaging.DETACHED == signaturePackaging)) && level.startsWith("XADES")) {

			final String form = "xades";
			final String levelOnly = DSSUtils.replaceStrStr(level, "XADES-", "").toLowerCase();
			final String packaging = signaturePackaging.name().toLowerCase();
			return new File(parentDir, originalName + "-" + form + "-" + packaging + "-" + levelOnly + ".xml");
		}

		if (level.startsWith("CADES") && !originalExtension.toLowerCase().equals(".p7m")) {
			return new File(parentDir, originalName + originalExtension + ".p7m");
		}

		if (level.startsWith("ASIC_S")) {
			return new File(parentDir, originalName + originalExtension + ".asics");
		}
		if (level.startsWith("ASIC_E")) {
			return new File(parentDir, originalName + originalExtension + ".asice");
		}

		return new File(parentDir, originalName + "-signed" + originalExtension);

	}
}
