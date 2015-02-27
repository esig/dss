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

package eu.europa.ec.markt.dss.applet.wizard.extension;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.applet.model.ExtendSignatureModel;
import eu.europa.ec.markt.dss.applet.model.FormatType;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.ControllerException;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
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
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#finish()
	 */
	@Override
	protected void finish() throws ControllerException {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getBackStep()
	 */
	@Override
	protected Class<? extends WizardStep<ExtendSignatureModel, ExtensionWizardController>> getBackStep() {
		return FileStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
	 */
	@Override
	protected Class<? extends WizardStep<ExtendSignatureModel, ExtensionWizardController>> getNextStep() {
		return SaveStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getStepProgression()
	 */
	@Override
	protected int getStepProgression() {
		return 2;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
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
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
	 */
	@Override
	protected boolean isValid() {
		final ExtendSignatureModel model = getModel();
		return DSSUtils.isNotEmpty(model.getFormat()) && model.getPackaging() != null && DSSUtils.isNotEmpty(model.getLevel());
	}
}
