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

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.RevocationStatusInformationType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportDataType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cryptographic signature is valid with expired certificate
 *
 */
public class CAdESLevelBWithExpiredCertificateAndRevokedContentTimestampTest extends AbstractCAdESTestSignature {

	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
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
	protected CertificateVerifier getCompleteCertificateVerifier() {
		CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
		certificateVerifier.setRevocationFallback(true);
		return certificateVerifier;
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
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subIndication);
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getTimestampIds().get(0));
		XmlXCV xcv = signatureBBB.getXCV();
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.REVOKED_NO_POE, xcv.getConclusion().getSubIndication());
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
				assertEquals(Indication.INDETERMINATE, signatureValidationStatus.getMainIndication());
				assertEquals(SubIndication.REVOKED_NO_POE, signatureValidationStatus.getSubIndication().get(0));

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
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
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
