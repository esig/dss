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
package eu.europa.esig.dss.cades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.jaxb.validationreport.RevocationStatusInformationType;
import eu.europa.esig.jaxb.validationreport.SignatureValidationReportType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectListType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectType;
import eu.europa.esig.jaxb.validationreport.ValidationReportDataType;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;
import eu.europa.esig.jaxb.validationreport.ValidationStatusType;
import eu.europa.esig.jaxb.validationreport.enums.MainIndication;
import eu.europa.esig.jaxb.validationreport.enums.ObjectType;

/**
 * Cryptographic signature is valid with expired certificate
 *
 */
public class CAdESLevelBWithExpiredCertificateAndRevokedContentTimestampTest extends AbstractCAdESTestSignature {

	private DocumentSignatureService<CAdESSignatureParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getRevokedTsa());

		documentToSign = new InMemoryDocument("Hello World".getBytes());

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
		signatureParameters.setSignWithExpiredCertificate(true);

		TimestampToken contentTimestamp = service.getContentTimestamp(documentToSign, signatureParameters);
		List<TimestampToken> contentTimestamps = Arrays.asList(contentTimestamp);
		signatureParameters.setContentTimestamps(contentTimestamps);

	}

	@Override
	protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier()); // force validation of the revoked TSA
		return validator;
	}

	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		Indication indication = simpleReport.getIndication(simpleReport.getFirstSignatureId());
		assertEquals(Indication.INDETERMINATE, indication);
		SubIndication subIndication = simpleReport.getSubIndication(simpleReport.getFirstSignatureId());
		assertEquals(SubIndication.NO_POE, subIndication);
	}

	@Override
	protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
		super.verifyETSIValidationReport(etsiValidationReportJaxb);

		boolean foundRevokedTsaInfo = false;
		ValidationObjectListType validationObjects = etsiValidationReportJaxb.getSignatureValidationObjects();
		for (ValidationObjectType vo : validationObjects.getValidationObject()) {
			if (ObjectType.TIMESTAMP.equals(vo.getObjectType())) {
				SignatureValidationReportType validationReport = vo.getValidationReport();
				ValidationStatusType signatureValidationStatus = validationReport.getSignatureValidationStatus();
				assertEquals(MainIndication.INDETERMINATE, signatureValidationStatus.getMainIndication());
				assertEquals(eu.europa.esig.jaxb.validationreport.enums.SubIndication.REVOKED_NO_POE, signatureValidationStatus.getSubIndication().get(0));

				List<ValidationReportDataType> associatedValidationReportData = signatureValidationStatus.getAssociatedValidationReportData();
				ValidationReportDataType validationReportDataType = associatedValidationReportData.get(0);
				RevocationStatusInformationType revocationStatusInformation = validationReportDataType.getRevocationStatusInformation();
				if (revocationStatusInformation != null) {
					foundRevokedTsaInfo = true;
				}
			}
		}
		assertTrue(foundRevokedTsaInfo);
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return EXPIRED_USER;
	}

}
