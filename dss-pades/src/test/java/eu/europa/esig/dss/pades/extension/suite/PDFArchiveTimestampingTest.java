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
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import eu.europa.esig.validationreport.jaxb.ValidationConstraintsEvaluationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PDFArchiveTimestampingTest extends PKIFactoryAccess {
	
	@Test
	void test() throws Exception {

		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		String originalDocDigestBase64 = Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, doc));
		
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		PAdESSignatureParameters extendParams = new PAdESSignatureParameters();
		
		extendParams.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
		extendParams.setSigningCertificate(getSigningCert());

		Exception exception = assertThrows(IllegalInputException.class, () -> service.extendDocument(doc, extendParams));
		assertEquals("No signatures found to be extended!", exception.getMessage());

		DSSDocument extendedDoc = service.timestamp(doc, new PAdESTimestampParameters());

		awaitOneSecond();

		extendParams.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		extendParams.setSigningCertificate(getSigningCert());
		exception = assertThrows(IllegalInputException.class, () -> service.extendDocument(extendedDoc, extendParams));
		assertEquals("No signatures found to be extended!", exception.getMessage());
		
		PDFDocumentValidator validator = new PDFDocumentValidator(extendedDoc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		// reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		
		assertEquals(0, simpleReport.getSignaturesCount());
		assertEquals(0, simpleReport.getSignatureIdList().size());
		
		assertEquals(1, simpleReport.getTimestampIdList().size());
		for (String timestampId : simpleReport.getTimestampIdList()) {
			assertEquals(Indication.PASSED, simpleReport.getIndication(timestampId));
		}
		
		DetailedReport detailedReport = reports.getDetailedReport();
		for (String timestampId : simpleReport.getTimestampIdList()) {
			assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestampId));
		}
		assertNull(detailedReport.getFirstSignatureId());
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		assertEquals(1, diagnosticData.getTimestampIdList().size());
		
		for (TimestampWrapper timestampWrapper : timestampList) {
			assertEquals(TimestampType.DOCUMENT_TIMESTAMP, timestampWrapper.getType());

			CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
			assertNotNull(signingCertificate);
			
			List<CertificateSourceType> sources = signingCertificate.getSources();
			assertTrue(Utils.isCollectionNotEmpty(sources));
			boolean timestampSource = false;
			for (CertificateSourceType source : sources) {
				if (CertificateSourceType.TIMESTAMP.equals(source)) {
					timestampSource = true;
					break;
				}
			}
			assertTrue(timestampSource);
			
			assertEquals(1, timestampWrapper.getTimestampedSignedData().size());
		}
		
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatures()));
		assertEquals(0, diagnosticData.getOriginalSignerDocuments().size());

		List<SignerDataWrapper> originalDocuments = diagnosticData.getAllSignerDocuments();
		assertEquals(1, originalDocuments.size());
		boolean fullDocFound = false;
		for (SignerDataWrapper signerData : originalDocuments) {
			if ("Full PDF".equals(signerData.getReferencedName())) {
				assertEquals(originalDocDigestBase64, Utils.toBase64(signerData.getDigestAlgoAndValue().getDigestValue()));
				fullDocFound = true;
			}
		}
		assertTrue(fullDocFound);
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReport.getSignatureValidationReport();
		assertNotNull(signatureValidationReports);
		assertEquals(1, signatureValidationReports.size());
		SignatureValidationReportType signatureValidationReport = signatureValidationReports.get(0);
		ValidationStatusType signatureValidationStatus = signatureValidationReport.getSignatureValidationStatus();
		assertNotNull(signatureValidationStatus);
		assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication());
		
		ValidationObjectListType validationObjects = etsiValidationReport.getSignatureValidationObjects();
		assertNotNull(validationObjects);
		assertTrue(Utils.isCollectionNotEmpty(validationObjects.getValidationObject()));
		int certificatesCounter = 0;
		int revocationCounter = 0;
		int timestampCounter = 0;
		int signerDataCounter = 0;
		for (ValidationObjectType validationObject : validationObjects.getValidationObject()) {
			switch (validationObject.getObjectType()) {
				case CERTIFICATE:
					++certificatesCounter;
					break;
				case CRL:
				case OCSP_RESPONSE:
					++revocationCounter;
					break;
				case TIMESTAMP:
					++timestampCounter;
					break;
				case SIGNED_DATA:
					++signerDataCounter;
					break;
				default:
					break;
			}
		}
		assertEquals(diagnosticData.getUsedCertificates().size(), certificatesCounter);
		assertEquals(diagnosticData.getAllRevocationData().size(), revocationCounter);
		assertEquals(diagnosticData.getTimestampList().size(), timestampCounter);
		assertEquals(diagnosticData.getAllSignerDocuments().size(), signerDataCounter);
		
		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReportJaxb);
		boolean noTimestamp = true;
		for (ValidationObjectType validationObject : etsiValidationReportJaxb.getSignatureValidationObjects().getValidationObject()) {
			if (ObjectType.TIMESTAMP == validationObject.getObjectType()) {
				noTimestamp = false;
				POEProvisioningType poeProvisioning = validationObject.getPOEProvisioning();
				assertNotNull(poeProvisioning);
				assertNotNull(poeProvisioning.getPOETime());
				assertTrue(Utils.isCollectionNotEmpty(poeProvisioning.getValidationObject()));

				SignatureValidationReportType validationReport = validationObject.getValidationReport();
				assertNotNull(validationReport);
				assertNotNull(validationReport.getSignatureQuality());
				assertTrue(Utils.isCollectionNotEmpty(validationReport.getSignatureQuality().getSignatureQualityInformation()));

				SignerInformationType signerInformation = validationReport.getSignerInformation();
				assertNotNull(signerInformation);
				assertNotNull(signerInformation.getSigner());
				assertNotNull(signerInformation.getSignerCertificate());

				ValidationStatusType timestampValidationStatus = validationReport.getSignatureValidationStatus();
				assertNotNull(timestampValidationStatus);
				assertNotNull(timestampValidationStatus.getMainIndication());
				assertNotNull(timestampValidationStatus.getAssociatedValidationReportData());
				assertNotNull(timestampValidationStatus.getAssociatedValidationReportData().get(0).getCryptoInformation());

				ValidationConstraintsEvaluationReportType validationConstraintsEvaluationReport = validationReport.getValidationConstraintsEvaluationReport();
				assertNotNull(validationConstraintsEvaluationReport);
				assertTrue(Utils.isCollectionNotEmpty(validationConstraintsEvaluationReport.getValidationConstraint()));
			}
		}
		assertFalse(noTimestamp);

	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
