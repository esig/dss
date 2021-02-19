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
package eu.europa.esig.dss.asic.cades.timestamp.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import eu.europa.esig.validationreport.jaxb.ValidationConstraintsEvaluationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCETimestampOneFileTest extends PKIFactoryAccess {

	@Test
	public void test() throws IOException {
		DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());

		DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);

		ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
		timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		DSSDocument archiveWithTimestamp = service.timestamp(documentToSign, timestampParameters);
		assertNotNull(archiveWithTimestamp);

//		archiveWithTimestamp.save("target/test-one-file.asice");

		final DSSDocument docToExtend = archiveWithTimestamp;
		ASiCWithCAdESSignatureParameters extendParameters = new ASiCWithCAdESSignatureParameters();
		extendParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		extendParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		DSSException exception = assertThrows(DSSException.class, () -> service.extendDocument(docToExtend, extendParameters));
		assertEquals("No supported signature documents found! Unable to extend the container.", exception.getMessage());
		extendParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		assertThrows(DSSException.class, () -> service.extendDocument(docToExtend, extendParameters));
		extendParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		assertThrows(DSSException.class, () -> service.extendDocument(docToExtend, extendParameters));

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(archiveWithTimestamp);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

//		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(0, diagnosticData.getSignatureIdList().size());
		assertEquals(1, diagnosticData.getTimestampIdList().size());

		signaturesAndTimestampsIntact(diagnosticData);

		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		ToBeSigned dataToSign = service.getDataToSign(archiveWithTimestamp, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument timestampedAndSigned = service.signDocument(archiveWithTimestamp, signatureParameters, signatureValue);

//		timestampedAndSigned.save("target/test-one-file-2-times-signed.asice");

		validator = SignedDocumentValidator.fromDocument(timestampedAndSigned);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		assertNotNull(reports);

//		reports.print();

		diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getSignatureIdList().size());
		assertEquals(1, diagnosticData.getTimestampIdList().size());

		signaturesAndTimestampsIntact(diagnosticData);

		timestampParameters = new ASiCWithCAdESTimestampParameters();
		timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		archiveWithTimestamp = service.timestamp(timestampedAndSigned, timestampParameters);

//		archiveWithTimestamp.save("target/test-one-file-2-times.asice");

		validator = SignedDocumentValidator.fromDocument(archiveWithTimestamp);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		assertNotNull(reports);

//		reports.print();

		diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getSignatureIdList().size());
		assertEquals(2, diagnosticData.getTimestampIdList().size());

		signaturesAndTimestampsIntact(diagnosticData);

		signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		dataToSign = service.getDataToSign(archiveWithTimestamp, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		timestampedAndSigned = service.signDocument(archiveWithTimestamp, signatureParameters, signatureValue);

//		timestampedAndSigned.save("target/test-one-file-2-times-signed.asice");

		validator = SignedDocumentValidator.fromDocument(timestampedAndSigned);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		assertNotNull(reports);

//		reports.print();

		diagnosticData = reports.getDiagnosticData();
		assertEquals(2, diagnosticData.getSignatureIdList().size());
		assertEquals(2, diagnosticData.getTimestampIdList().size());

		signaturesAndTimestampsIntact(diagnosticData);

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

	private void signaturesAndTimestampsIntact(DiagnosticData diagnosticData) {

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertTrue(signature.isSignatureIntact());
			assertTrue(signature.isSignatureValid());
		}

		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			assertTrue(timestamp.isSignatureIntact());
			assertTrue(timestamp.isSignatureValid());

			assertEquals(2, timestamp.getDigestMatchers().size());
			assertEquals(2, timestamp.getTimestampedSignedData().size());
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
