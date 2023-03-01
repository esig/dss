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
package eu.europa.esig.dss.ws.validation.common;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RemoteDocumentValidationServiceTest {

	RemoteDocumentValidationService validationService;

	@BeforeEach
	public void init() {
		validationService = new RemoteDocumentValidationService();
		validationService.setVerifier(new CommonCertificateVerifier());
	}

	@Test
	public void testWithNoPolicyAndNoOriginalFile() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xadesLTA.xml"));
		DataToValidateDTO dto = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);
		WSReportsDTO result = validationService.validateDocument(dto);
		validateReports(result);
	}

	@Test
	public void testWithNoPolicyAndNoOriginalFileAndStrategy() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xadesLTA.xml"));
		DataToValidateDTO dto = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);
		dto.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_ONLY);
		WSReportsDTO result = validationService.validateDocument(dto);
		validateReports(result);
	}

	@Test
	public void testWithNoPolicyAndOriginalFile() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
		RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.png"));
		DataToValidateDTO dto = new DataToValidateDTO(signedFile, originalFile, null);
		WSReportsDTO result = validationService.validateDocument(dto);
		validateReports(result);
	}

	@Test
	public void testWithNoPolicyAndDigestOriginalFile() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
		FileDocument fileDocument = new FileDocument("src/test/resources/sample.png");
		RemoteDocument originalFile = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileDocument), DigestAlgorithm.SHA256, fileDocument.getName());
		DataToValidateDTO dto = new DataToValidateDTO(signedFile, originalFile, null);
		WSReportsDTO result = validationService.validateDocument(dto);
		validateReports(result);
		assertEquals("QES AdESQC TL based", result.getSimpleReport().getValidationPolicy().getPolicyName());
	}

	@Test
	public void testWithPolicyAndOriginalFile() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
		RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.png"));
		RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));
		DataToValidateDTO dto = new DataToValidateDTO(signedFile, originalFile, policy);
		WSReportsDTO result = validationService.validateDocument(dto);
		validateReports(result);
		assertEquals("QES AdESQC TL based (Test WebServices)", result.getSimpleReport().getValidationPolicy().getPolicyName());
	}

	@Test
	public void testWithDefaultPolicyAndOriginalFile() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
		RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.png"));

		Unmarshaller unmarshaller = ValidationPolicyFacade.newFacade().getUnmarshaller(true);
		JAXBElement<ConstraintsParameters> unmarshal = (JAXBElement<ConstraintsParameters>) unmarshaller
				.unmarshal(ValidationPolicyFacade.class.getResourceAsStream("/constraint.xml"));

		ConstraintsParameters constraints = unmarshal.getValue();
		constraints.setName("Default Policy");

		RemoteDocumentValidationService validationService = new RemoteDocumentValidationService();
		validationService.setVerifier(new CommonCertificateVerifier());
		validationService.setDefaultValidationPolicy(new EtsiValidationPolicy(constraints));

		DataToValidateDTO dto = new DataToValidateDTO(signedFile, originalFile, null);
		WSReportsDTO result = validationService.validateDocument(dto);
		validateReports(result);
		assertEquals("Default Policy", result.getSimpleReport().getValidationPolicy().getPolicyName());
	}

	@Test
	public void testWithOverwrittenDefaultPolicyAndOriginalFile() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
		RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.png"));
		RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));

		Unmarshaller unmarshaller = ValidationPolicyFacade.newFacade().getUnmarshaller(true);
		JAXBElement<ConstraintsParameters> unmarshal = (JAXBElement<ConstraintsParameters>) unmarshaller
				.unmarshal(ValidationPolicyFacade.class.getResourceAsStream("/constraint.xml"));

		ConstraintsParameters constraints = unmarshal.getValue();
		constraints.setName("Default Policy");

		RemoteDocumentValidationService validationService = new RemoteDocumentValidationService();
		validationService.setVerifier(new CommonCertificateVerifier());
		validationService.setDefaultValidationPolicy(new EtsiValidationPolicy(constraints));

		DataToValidateDTO dto = new DataToValidateDTO(signedFile, originalFile, policy);
		WSReportsDTO result = validationService.validateDocument(dto);
		validateReports(result);
		assertEquals("QES AdESQC TL based (Test WebServices)", result.getSimpleReport().getValidationPolicy().getPolicyName());
	}

	@Test
	public void testWithPolicyAndNoOriginalFile() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
		RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));
		DataToValidateDTO dto = new DataToValidateDTO(signedFile, (RemoteDocument) null, policy);
		WSReportsDTO result = validationService.validateDocument(dto);

		assertNotNull(result.getDiagnosticData());
		assertNotNull(result.getDetailedReport());
		assertNotNull(result.getSimpleReport());
		assertNotNull(result.getValidationReport());

		assertEquals(1, result.getSimpleReport().getSignaturesCount());
		assertEquals(2, result.getDiagnosticData().getSignatures().get(0).getFoundTimestamps().size());
		assertEquals(Indication.INDETERMINATE, result.getSimpleReport().getSignatureOrTimestamp().get(0).getIndication());

		Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(), result.getValidationReport());

		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticData());
		assertNotNull(reports.getDetailedReport());
		assertNotNull(reports.getSimpleReport());

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertEquals(SignatureLevel.XAdES_BASELINE_LTA, signature.getSignatureFormat());

		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
		assertFalse(signature.isBLevelTechnicallyValid()); // no original data provided
	}

	@Test
	public void testGetOriginals() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xadesLTA.xml"));
		DataToValidateDTO dto = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);
		WSReportsDTO reports = validationService.validateDocument(dto);
		String signatureId = reports.getDiagnosticData().getSignatures().get(0).getId();

		dto = new DataToValidateDTO(signedFile, (RemoteDocument) null, null, signatureId);
		List<RemoteDocument> result = validationService.getOriginalDocuments(dto);
		assertNotNull(result);
		assertEquals(1, result.size());
		RemoteDocument document = result.get(0);
		assertNotNull(document);
		assertNotNull(document.getBytes());
	}

	@Test
	public void testGetOriginalsWithoutId() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xadesLTA.xml"));
		DataToValidateDTO dto = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);
		// returns original signer data of the first signature
		List<RemoteDocument> result = validationService.getOriginalDocuments(dto);
		assertNotNull(result);
		assertEquals(1, result.size());
		RemoteDocument document = result.get(0);
		assertNotNull(document);
		assertNotNull(document.getBytes());
	}

	@Test
	public void testGetOriginalsWithWrongId() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xadesLTA.xml"));
		DataToValidateDTO dto = new DataToValidateDTO(signedFile, (RemoteDocument) null, null, "id-wrong");
		List<RemoteDocument> result = validationService.getOriginalDocuments(dto);
		assertNotNull(result);
		assertEquals(0, result.size());
	}

	@Test
	public void testGetOriginalFromDetachedSignature() throws Exception {
		RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
		RemoteDocument originalDocument = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.png"));
		DataToValidateDTO dto = new DataToValidateDTO(signedFile, Arrays.asList(originalDocument), null);

		List<RemoteDocument> result = validationService.getOriginalDocuments(dto);
		assertNotNull(result);
		assertEquals(1, result.size());
		RemoteDocument document = result.get(0);
		assertNotNull(document);
		assertArrayEquals(DSSUtils.toByteArray(RemoteDocumentConverter.toDSSDocument(originalDocument)), document.getBytes());
	}

	private void validateReports(WSReportsDTO result) {
		assertNotNull(result.getDiagnosticData());
		assertNotNull(result.getDetailedReport());
		assertNotNull(result.getSimpleReport());
		assertNotNull(result.getValidationReport());

		assertEquals(1, result.getSimpleReport().getSignaturesCount());
		assertEquals(2, result.getDiagnosticData().getSignatures().get(0).getFoundTimestamps().size());
		assertEquals(Indication.INDETERMINATE, result.getSimpleReport().getSignatureOrTimestamp().get(0).getIndication());

		Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(), result.getValidationReport());

		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticData());
		assertNotNull(reports.getDetailedReport());
		assertNotNull(reports.getSimpleReport());

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertEquals(SignatureLevel.XAdES_BASELINE_LTA, signature.getSignatureFormat());

		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}
		assertTrue(signature.isBLevelTechnicallyValid());
	}

}
