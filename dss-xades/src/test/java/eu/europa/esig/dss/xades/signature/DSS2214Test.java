/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class DSS2214Test extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new FileDocument("src/test/resources/sample.xml");

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
		certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
		service = new XAdESService(certificateVerifier);
	}

	@Override
	protected Reports verify(DSSDocument signedDocument) {
		SignedDocumentValidator validator = getValidator(signedDocument);
		// revocation data are needed for this test
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument(getModifiedValidationPolicy());

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertNotEquals(0, diagnosticData.getAllRevocationData().size());

		verifyDiagnosticData(diagnosticData);

		verifyDiagnosticDataJaxb(reports.getDiagnosticDataJaxb());

		runDifferentValidationLevels(reports.getDiagnosticDataJaxb());

		SimpleReport simpleReport = reports.getSimpleReport();
		verifySimpleReport(simpleReport);

		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		verifyDetailedReport(detailedReport);

		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		verifyETSIValidationReport(etsiValidationReportJaxb);

		verifyReportsData(reports);

		return reports;
	}

	@SuppressWarnings("unchecked")
	private EtsiValidationPolicy getModifiedValidationPolicy() {
		try {
			EtsiValidationPolicy validationPolicy = (EtsiValidationPolicy) ValidationPolicyLoader.fromDefaultValidationPolicy().create();

			SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
			BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();
			basicSignatureConstraints.getSigningCertificate().getAcceptableRevocationDataFound().setLevel(Level.WARN);
			basicSignatureConstraints.getCACertificate().getAcceptableRevocationDataFound().setLevel(Level.WARN);

			return validationPolicy;

		} catch (Exception e) {
			throw new DSSException("Unable to build a custom policy", e);
		}
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
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
	protected String getSigningAlias() {
		return EXPIRED_USER;
	}

}
