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
package eu.europa.ec.markt.dss.applet.wizard.validation;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.applet.controller.ActivityController;
import eu.europa.ec.markt.dss.applet.controller.DSSWizardController;
import eu.europa.ec.markt.dss.applet.main.DSSAppletCore;
import eu.europa.ec.markt.dss.applet.main.Parameters;
import eu.europa.ec.markt.dss.applet.model.ValidationModel;
import eu.europa.ec.markt.dss.applet.util.SimpleReportConverter;
import eu.europa.ec.markt.dss.applet.util.ValidationPolicyDao;
import eu.europa.ec.markt.dss.applet.util.ValidationReportConverter;
import eu.europa.ec.markt.dss.applet.view.validation.ReportView;
import eu.europa.ec.markt.dss.applet.view.validation.ValidationView;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import eu.europa.ec.markt.dss.ws.validation.DSSException_Exception;
import eu.europa.ec.markt.dss.ws.validation.ObjectFactory;
import eu.europa.ec.markt.dss.ws.validation.ValidationService;
import eu.europa.ec.markt.dss.ws.validation.ValidationService_Service;
import eu.europa.ec.markt.dss.ws.validation.WsDocument;
import eu.europa.ec.markt.dss.ws.validation.WsValidationReport;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */

public class ValidationWizardController extends DSSWizardController<ValidationModel> {

	private static ObjectFactory FACTORY;

	static {

		System.setProperty("javax.xml.bind.JAXBContext", "com.sun.xml.internal.bind.v2.ContextFactory");
		FACTORY = new ObjectFactory();

	}

	private ReportView reportView;

	private ValidationView formView;

	/**
	 * The default constructor for ValidationWizardController.
	 *
	 * @param core
	 * @param model
	 */
	public ValidationWizardController(final DSSAppletCore core, final ValidationModel model) {

		super(core, model);
		final Parameters parameters = core.getParameters();
	}

	/**
	 *
	 */
	public void displayFormView() {
		formView.show();
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.ecodex.dss.commons.swing.mvc.applet.WizardController#doCancel()
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
	protected Class<? extends WizardStep<ValidationModel, ? extends WizardController<ValidationModel>>> doStart() {
		return FormStep.class;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#registerViews()
	 */
	@Override
	protected void registerViews() {
		formView = new ValidationView(getCore(), this, getModel());
		reportView = new ReportView(getCore(), this, getModel());
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#registerWizardStep()
	 */
	@Override
	protected Map<Class<? extends WizardStep<ValidationModel, ? extends WizardController<ValidationModel>>>, ? extends WizardStep<ValidationModel, ? extends WizardController<ValidationModel>>> registerWizardStep() {
		final Map steps = new HashMap();
		steps.put(FormStep.class, new FormStep(getModel(), formView, this));
		steps.put(ReportStep.class, new ReportStep(getModel(), reportView, this));
		return steps;
	}

	/**
	 * Validate the document with the 102853 validation policy
	 *
	 * @throws IOException
	 */
	public void validateDocument() throws DSSException {

		final ValidationModel model = getModel();

		final File signedFile = model.getSignedFile();
		final WsDocument wsSignedDocument = toWsDocument(signedFile);

		final File detachedFile = model.getOriginalFile();
		final WsDocument wsDetachedDocument = detachedFile != null ? toWsDocument(detachedFile) : null;

		WsDocument wsPolicyDocument = null;
		if (!model.isDefaultPolicy() && (model.getSelectedPolicyFile() != null)) {

			final File policyFile = new File(model.getSelectedPolicyFile().getAbsolutePath());
			final InputStream inputStream = DSSUtils.toInputStream(policyFile);
			wsPolicyDocument = new WsDocument();
			wsPolicyDocument.setBytes(DSSUtils.toByteArray(inputStream));
		}

		//assertValidationPolicyFileValid(validationPolicyURL);

		ValidationService_Service.setROOT_SERVICE_URL(serviceURL);
		final ValidationService_Service validationService_service = new ValidationService_Service();
		final ValidationService validationServiceImplPort = validationService_service.getValidationServiceImplPort();
		final WsValidationReport wsValidationReport;
		try {
			wsValidationReport = validationServiceImplPort.validateDocument(wsSignedDocument, wsDetachedDocument, wsPolicyDocument, true);
		} catch (DSSException_Exception e) {
			throw new DSSException(e);
		} catch (Throwable e) {
			throw new DSSException(e);
		}

		String xmlData = "";
		try {

			// In case of some signatures, the returned data are not UTF-8 encoded. The conversion is forced.

			xmlData = wsValidationReport.getXmlDiagnosticData();
			// final String xmlDiagnosticData = DSSUtils.getUtf8String(xmlData);
			final XmlDom diagnosticDataXmlDom = getXmlDomReport(xmlData);
			model.setDiagnosticData(diagnosticDataXmlDom);

			xmlData = "";
			xmlData = wsValidationReport.getXmlDetailedReport();
			// final String xmlDetailedReport = DSSUtils.getUtf8String(xmlData);
			final XmlDom detailedReportXmlDom = getXmlDomReport(xmlData);
			model.setDetailedReport(detailedReportXmlDom);

			xmlData = "";
			xmlData = wsValidationReport.getXmlSimpleReport();
			// final String xmlSimpleReport = DSSUtils.getUtf8String(xmlData);
			final XmlDom simpleReportXmlDom = getXmlDomReport(xmlData);
			model.setSimpleReport(simpleReportXmlDom);
		} catch (Exception e) {

			final String base64Encode = Base64.encodeBase64String(xmlData.getBytes());
			LOG.error("Erroneous data: " + base64Encode);
			if (e instanceof DSSException) {
				throw (DSSException) e;
			}
			throw new DSSException(e);
		}
	}

	private WsDocument toWsDocument(final File detachedFile) {

		final FileDocument dssDocument = new FileDocument(detachedFile);

		final WsDocument wsDocument = new WsDocument();
		wsDocument.setBytes(dssDocument.getBytes());
		wsDocument.setName(dssDocument.getName());
		wsDocument.setAbsolutePath(dssDocument.getAbsolutePath());
		final MimeType mimeType = dssDocument.getMimeType();
		final eu.europa.ec.markt.dss.ws.validation.MimeType wsMimeType = FACTORY.createMimeType();
		final String mimeTypeString = mimeType.getMimeTypeString();
		wsMimeType.setMimeTypeString(mimeTypeString);
		wsDocument.setMimeType(wsMimeType);
		return wsDocument;
	}

	private XmlDom getXmlDomReport(final String report) {

		// System.out.println("############################ 2");
		final Document reportDom = DSSXMLUtils.buildDOM(report);
		return new XmlDom(reportDom);
	}

	private void assertValidationPolicyFileValid(URL validationPolicyURL, URL xsdUrl) {
		try {
			new ValidationPolicyDao().load(validationPolicyURL.openStream(), xsdUrl.openStream());
		} catch (Exception e) {
			throw new DSSException("The selected Validation Policy is not valid.");
		}
	}

	public Document renderSimpleReportAsHtml() {
		final XmlDom simpleReport = getModel().getSimpleReport();
		final SimpleReportConverter simpleReportConverter = new SimpleReportConverter();
		return simpleReportConverter.renderAsHtml(simpleReport);
	}

	public Document renderValidationReportAsHtml() {
		final XmlDom detailedReport = getModel().getDetailedReport();
		final ValidationReportConverter validationReportConverter = new ValidationReportConverter();
		return validationReportConverter.renderAsHtml(detailedReport);
	}

}
