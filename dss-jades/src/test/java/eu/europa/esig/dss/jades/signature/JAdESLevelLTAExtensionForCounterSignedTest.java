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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESLevelLTAExtensionForCounterSignedTest extends AbstractJAdESTestValidation {
	
	private JAdESService service;
	private DSSDocument documentToSign;
	private JAdESSignatureParameters signatureParameters;
	private JAdESCounterSignatureParameters counterSignatureParameters;
	
	private String signingAlias;
	
	@BeforeEach
	public void init() {
		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		
		signingAlias = SELF_SIGNED_USER;
		
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		
		signingAlias = GOOD_USER;
		
		counterSignatureParameters = new JAdESCounterSignatureParameters();
		counterSignatureParameters.bLevel().setSigningDate(new Date());
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		counterSignatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
	}
	
	@Test
	public void test() throws Exception {
		signingAlias = SELF_SIGNED_USER;
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				signatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		signingAlias = GOOD_USER;

		SignedDocumentValidator validator = getValidator(signedDocument);
		String mainSignatureId = validator.getSignatures().get(0).getId();
		
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);
		
		ToBeSigned dataToBeCounterSigned = service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters);
		signatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(),
				counterSignatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument counterSignedSignature = service.counterSignSignature(signedDocument, counterSignatureParameters, signatureValue);
		
		validator = getValidator(counterSignedSignature);
		assertEquals(mainSignatureId, validator.getSignatures().get(0).getId());
		assertEquals(1, validator.getSignatures().get(0).getCounterSignatures().size());
		
		String counterSignatureId = validator.getSignatures().get(0).getCounterSignatures().get(0).getId();
		assertNotEquals(mainSignatureId, counterSignatureId);
		
		// counterSignedSignature.save("target/counterSignedSignature.json");
		
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);

		DSSDocument ltaJAdES = service.extendDocument(counterSignedSignature, signatureParameters);
		
		// ltaJAdES.save("target/ltaJAdES.json");
		
		Reports reports = verify(ltaJAdES);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(mainSignatureId);
		assertNotNull(signatureWrapper);
		assertFalse(signatureWrapper.isCounterSignature());
		assertEquals(SignatureLevel.JAdES_BASELINE_LTA, signatureWrapper.getSignatureFormat());
		
		Set<SignatureWrapper> counterSignatures = diagnosticData.getAllCounterSignaturesForMasterSignature(signatureWrapper);
		assertEquals(1, counterSignatures.size());
		
		SignatureWrapper counterSignature = counterSignatures.iterator().next();
		assertEquals(counterSignatureId, counterSignature.getId());
		assertEquals(SignatureLevel.JAdES_BASELINE_B, counterSignature.getSignatureFormat());
		
		counterSignatureParameters.setSignatureIdToCounterSign(counterSignature.getId());
		Exception exception = assertThrows(IllegalInputException.class, () -> service.getDataToBeCounterSigned(ltaJAdES, counterSignatureParameters));
		assertEquals(String.format("Unable to counter sign a signature with Id '%s'. "
				+ "The signature is timestamped by a master signature!", counterSignature.getId()), exception.getMessage());
		
		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
		List<String> certificateValuesIds = foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES)
				.stream().map(c -> c.getId()).collect(Collectors.toList());
		for (CertificateWrapper certificateWrapper : counterSignature.getCertificateChain()) {
			assertTrue(certificateValuesIds.contains(certificateWrapper.getId()));
		}
		
		assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES)));
		
		assertTrue(counterSignature.getSigningCertificate().isRevocationDataAvailable());
		
		// possible to counter sign the main signature again
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);
		dataToBeCounterSigned = service.getDataToBeCounterSigned(ltaJAdES, counterSignatureParameters);
		signatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(),
				counterSignatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		counterSignedSignature = service.counterSignSignature(ltaJAdES, counterSignatureParameters, signatureValue);
		assertNotNull(counterSignedSignature);
		
		validator = getValidator(counterSignedSignature);
		assertEquals(1, validator.getSignatures().size());
		
		AdvancedSignature mainSignature = validator.getSignatures().get(0);
		assertEquals(mainSignatureId, mainSignature.getId());
		
		assertEquals(2, mainSignature.getCounterSignatures().size());
		assertEquals(counterSignatureId, mainSignature.getCounterSignatures().get(0).getId());
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		assertEquals(1, signatures.size());
		
		AdvancedSignature advancedSignature = signatures.get(0);
		List<AdvancedSignature> counterSignatures = advancedSignature.getCounterSignatures();
		assertEquals(1, counterSignatures.size());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		Set<SignatureWrapper> counterSignatures = diagnosticData.getAllCounterSignatures();
		assertEquals(1, counterSignatures.size());
		SignatureWrapper counterSignature = counterSignatures.iterator().next();
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		
		boolean sigTstFound = false;
		boolean arcTstFound = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
				assertFalse(timestampWrapper.getTimestampedSignatures().stream().map(s -> s.getId()).collect(Collectors.toList())
						.contains(counterSignature.getId()));
				assertFalse(timestampWrapper.getTimestampedCertificates().stream().map(c -> c.getId()).collect(Collectors.toList())
						.contains(counterSignature.getSigningCertificate().getId()));
				sigTstFound = true;
				
			} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(2, timestampWrapper.getTimestampedSignatures().size());
				assertTrue(timestampWrapper.getTimestampedSignatures().stream().map(s -> s.getId()).collect(Collectors.toList())
						.contains(counterSignature.getId()));
				assertTrue(timestampWrapper.getTimestampedCertificates().stream().map(c -> c.getId()).collect(Collectors.toList())
						.contains(counterSignature.getSigningCertificate().getId()));
				arcTstFound = true;
				
			}
		}
		assertTrue(sigTstFound);
		assertTrue(arcTstFound);
	}
	
	@Override
	public void validate() {
		// do nothing
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return null;
	}
	
	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

}
