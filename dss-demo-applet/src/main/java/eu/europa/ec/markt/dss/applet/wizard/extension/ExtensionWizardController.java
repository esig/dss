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
package eu.europa.ec.markt.dss.applet.wizard.extension;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.applet.controller.ActivityController;
import eu.europa.ec.markt.dss.applet.main.DSSAppletCore;
import eu.europa.ec.markt.dss.applet.model.ExtendSignatureModel;
import eu.europa.ec.markt.dss.applet.util.SigningUtils;
import eu.europa.ec.markt.dss.applet.view.extension.FileView;
import eu.europa.ec.markt.dss.applet.view.extension.FinishView;
import eu.europa.ec.markt.dss.applet.view.extension.SaveView;
import eu.europa.ec.markt.dss.applet.view.extension.SignatureView;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.ws.signature.SignatureLevel;
import eu.europa.ec.markt.dss.ws.signature.WsParameters;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class ExtensionWizardController extends WizardController<ExtendSignatureModel> {

	private FileView fileView;
	private SignatureView signatureView;
	private SaveView saveView;
	private FinishView finishView;

	/**
	 * The default constructor for ExtendsWizardController.
	 *
	 * @param core
	 * @param model
	 */
	public ExtensionWizardController(final DSSAppletCore core, final ExtendSignatureModel model) {
		super(core, model);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#doCancel()
	 */
	@Override
	protected void doCancel() {
		getCore().getController(ActivityController.class).display();
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#doStart()
	 */
	@Override
	protected Class<? extends WizardStep<ExtendSignatureModel, ? extends WizardController<ExtendSignatureModel>>> doStart() {
		return FileStep.class;
	}

	/**
	 * @throws IOException
	 */
	public void extendAndSave() throws IOException {

		final ExtendSignatureModel model = getModel();
		final File signedFile = getModel().getSelectedFile();
		final File originalFile = getModel().getOriginalFile();

		final WsParameters parameters = new WsParameters();
		parameters.setSigningDate(DSSXMLUtils.createXMLGregorianCalendar(new Date()));
		parameters.setSignatureLevel(SignatureLevel.valueOf(model.getLevel()));
		parameters.setSignaturePackaging(model.getPackaging());

		final DSSDocument signedDocument = SigningUtils.extendDocument(serviceURL, signedFile, parameters);

		final InputStream inputStream = signedDocument.openStream();
		final FileOutputStream fileOutputStream = new FileOutputStream(model.getTargetFile());
		IOUtils.copy(inputStream, fileOutputStream);
		IOUtils.closeQuietly(inputStream);
		IOUtils.closeQuietly(fileOutputStream);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#registerViews()
	 */
	@Override
	protected void registerViews() {
		this.fileView = new FileView(getCore(), this, getModel());
		this.signatureView = new SignatureView(getCore(), this, getModel());
		this.saveView = new SaveView(getCore(), this, getModel());
		this.finishView = new FinishView(getCore(), this, getModel());
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#registerWizardStep()
	 */
	@Override
	protected Map<Class<? extends WizardStep<ExtendSignatureModel, ? extends WizardController<ExtendSignatureModel>>>, ? extends WizardStep<ExtendSignatureModel, ? extends WizardController<ExtendSignatureModel>>> registerWizardStep() {
		final Map steps = new HashMap();
		steps.put(FileStep.class, new FileStep(getModel(), fileView, this));
		steps.put(SignatureStep.class, new SignatureStep(getModel(), signatureView, this));
		steps.put(SaveStep.class, new SaveStep(getModel(), saveView, this));
		steps.put(FinishStep.class, new FinishStep(getModel(), finishView, this));
		return steps;
	}

}
