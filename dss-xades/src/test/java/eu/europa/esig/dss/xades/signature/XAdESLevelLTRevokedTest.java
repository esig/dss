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
package eu.europa.esig.dss.xades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRevocationInformation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.validationreport.jaxb.RevocationStatusInformationType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportDataType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;

public class XAdESLevelLTRevokedTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

		CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
		completeCertificateVerifier.setAlertOnRevokedCertificate(new LogOnStatusAlert());
		service = new XAdESService(completeCertificateVerifier);
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected String getSigningAlias() {
		return REVOKED_USER;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);

		String signatureId = detailedReport.getFirstSignatureId();
		XmlSubXCV subXCV = detailedReport.getSigningCertificate(signatureId);
		assertNotNull(subXCV);
		XmlRevocationInformation revocationInfo = subXCV.getRevocationInfo();
		assertNotNull(revocationInfo);
		assertNotNull(revocationInfo.getCertificateId());
		assertNotNull(revocationInfo.getRevocationId());
		assertNotNull(revocationInfo.getRevocationDate());
		assertNotNull(revocationInfo.getReason());
	}

	@Override
	protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
		super.verifyETSIValidationReport(etsiValidationReportJaxb);

		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReportJaxb.getSignatureValidationReport();
		SignatureValidationReportType signatureValidationReportType = signatureValidationReports.get(0);
		ValidationStatusType signatureValidationStatus = signatureValidationReportType.getSignatureValidationStatus();
		assertNotNull(signatureValidationStatus);
		List<ValidationReportDataType> associatedValidationReportData = signatureValidationStatus.getAssociatedValidationReportData();
		assertEquals(1, associatedValidationReportData.size());
		ValidationReportDataType validationReportDataType = associatedValidationReportData.get(0);
		RevocationStatusInformationType revocationStatusInformation = validationReportDataType.getRevocationStatusInformation();
		assertNotNull(revocationStatusInformation);
		assertNotNull(revocationStatusInformation.getRevocationObject());
		assertNotNull(revocationStatusInformation.getRevocationReason());
		assertNotNull(revocationStatusInformation.getRevocationTime());
		assertNotNull(revocationStatusInformation.getValidationObjectId());
	}

}
