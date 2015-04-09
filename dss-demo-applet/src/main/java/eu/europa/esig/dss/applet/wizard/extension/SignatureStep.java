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
package eu.europa.esig.dss.applet.wizard.extension;

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.applet.model.ExtendSignatureModel;
import eu.europa.esig.dss.applet.model.FormatType;
import eu.europa.esig.dss.applet.swing.mvc.ControllerException;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class SignatureStep extends WizardStep<ExtendSignatureModel, ExtensionWizardController> {

	/**
	 * The default constructor for SignatureStep.
	 *
	 * @param model
	 * @param view
	 * @param controller
	 */
	public SignatureStep(final ExtendSignatureModel model, final WizardView<ExtendSignatureModel, ExtensionWizardController> view, final ExtensionWizardController controller) {
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
	protected Class<? extends WizardStep<ExtendSignatureModel, ExtensionWizardController>> getBackStep() {
		return FileStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#getNextStep()
	 */
	@Override
	protected Class<? extends WizardStep<ExtendSignatureModel, ExtensionWizardController>> getNextStep() {
		return SaveStep.class;
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
	protected void init() throws ControllerException {

		final ExtendSignatureModel model = getModel();
		switch (model.getFileType()) {
			case ASiCS:
				model.setFormat(FormatType.ASICS);
				break;
			case ASiCE:
				model.setFormat(FormatType.ASICE);
				break;
			case BINARY:
				model.setFormat(FormatType.CADES);
				break;
			case CMS:
				model.setFormat(FormatType.CADES);
				break;
			case PDF:
				model.setFormat(FormatType.PADES);
				break;
			case XML:
				model.setFormat(FormatType.XADES);
				break;
			default:
				model.setFormat(FormatType.CADES);
				break;
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.wizard.WizardStep#isValid()
	 */
	@Override
	protected boolean isValid() {
		final ExtendSignatureModel model = getModel();
		return StringUtils.isNotEmpty(model.getFormat()) && (model.getPackaging() != null) && StringUtils.isNotEmpty(model.getLevel());
	}
}
