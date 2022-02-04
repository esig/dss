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
import eu.europa.esig.dss.asic.cades.validation.AbstractASiCWithCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
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
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ASiCETimestampMultiFilesTest extends AbstractASiCWithCAdESTestValidation {

	@Test
	public void test() throws IOException {
		ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());

		DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
		DSSDocument documentToSign2 = new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT);
		List<DSSDocument> docs = Arrays.asList(documentToSign, documentToSign2);

		ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
		timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		DSSDocument archiveWithTimestamp = service.timestamp(docs, timestampParameters);
		assertNotNull(archiveWithTimestamp);

//		archiveWithTimestamp.save("target/test-multi-files.asice");

		Reports reports = verify(archiveWithTimestamp);

//		reports.print();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData.getContainerInfo());
		assertEquals(ASiCContainerType.ASiC_E, diagnosticData.getContainerInfo().getContainerType());
		assertEquals(0, diagnosticData.getSignatureIdList().size());
		assertEquals(1, diagnosticData.getTimestampIdList().size());
		assertEquals(0, diagnosticData.getAllRevocationData().size()); // offline
		
		TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().get(0);
		assertTrue(timestampWrapper.isMessageImprintDataFound());
		assertTrue(timestampWrapper.isMessageImprintDataIntact());
		assertTrue(timestampWrapper.isSignatureIntact());
		assertTrue(timestampWrapper.isSignatureValid());
		
		List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
		assertEquals(3, digestMatchers.size());
		assertEquals(3, timestampWrapper.getTimestampedSignedData().size());

		int messageImprintCounter = 0;
		int filesCounter = 0;
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			assertNotNull(xmlDigestMatcher.getName());
			if (DigestMatcherType.MESSAGE_IMPRINT == xmlDigestMatcher.getType()) {
				messageImprintCounter++;
			} else if (DigestMatcherType.MANIFEST_ENTRY == xmlDigestMatcher.getType()) {
				filesCounter++;
			} else {
				fail("Not supported " + xmlDigestMatcher);
			}
		}
		assertEquals(1, messageImprintCounter);
		assertEquals(docs.size(), filesCounter);

		timestampParameters = new ASiCWithCAdESTimestampParameters();
		timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		archiveWithTimestamp = service.timestamp(archiveWithTimestamp, timestampParameters);

//		archiveWithTimestamp.save("target/test-multi-files-2-times.asice");

		reports = verify(archiveWithTimestamp);
		assertNotNull(reports);

//		reports.print();

		diagnosticData = reports.getDiagnosticData();
		assertEquals(0, diagnosticData.getSignatureIdList().size());
		assertEquals(2, diagnosticData.getTimestampIdList().size());

		boolean firstTstFound = false;
		boolean secondTstFound = false;
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			assertTrue(timestamp.isSignatureIntact());
			assertTrue(timestamp.isSignatureValid());

			if (timestamp.getDigestMatchers().size() == 3) {
				assertEquals(3, timestamp.getTimestampScopes().size());
				assertEquals(3, timestamp.getTimestampedSignedData().size());
				firstTstFound = true;

			} else if (timestamp.getDigestMatchers().size() == 5) {
				assertEquals(5, timestamp.getTimestampScopes().size());
				assertEquals(4, timestamp.getTimestampedSignedData().size());
				assertEquals(1, timestamp.getTimestampedTimestamps().size());
				secondTstFound = true;
			}
		}
		assertTrue(firstTstFound);
		assertTrue(secondTstFound);

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

		final DSSDocument docToExtend = archiveWithTimestamp;
		ASiCWithCAdESSignatureParameters extendParameters = new ASiCWithCAdESSignatureParameters();
		extendParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		extendParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		Exception exception = assertThrows(IllegalInputException.class, () -> service.extendDocument(docToExtend, extendParameters));
		assertEquals("No supported signature documents found! Unable to extend the container.", exception.getMessage());
		extendParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		assertThrows(IllegalInputException.class, () -> service.extendDocument(docToExtend, extendParameters));
		extendParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		assertThrows(IllegalInputException.class, () -> service.extendDocument(docToExtend, extendParameters));
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		assertTrue(Utils.isCollectionEmpty(signatures));
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatures()));
	}
	
	@Override
	protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
		assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication());
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return null;
	}
	
	@Override
	public void validate() {
		// do nothing
	}

}
