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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.validation.AbstractASiCWithXAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEXAdESLevelBNestedCounterSignatureTest extends AbstractASiCWithXAdESTestValidation {

	private DSSDocument documentToSign;
	private ASiCWithXAdESService service;
	private ASiCWithXAdESSignatureParameters signatureParameters;
	private XAdESCounterSignatureParameters counterSignatureParameters;
	
	@BeforeEach
	public void init() {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
		
		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		
		signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		
		counterSignatureParameters = new XAdESCounterSignatureParameters();
		counterSignatureParameters.bLevel().setSigningDate(new Date());
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
	}
	
	@Test
	public void test() throws Exception {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				signatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		Exception exception = assertThrows(NullPointerException.class, () -> service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters));
		assertEquals("The Id of a signature to be counter signed shall be defined! "
					+ "Please use SerializableCounterSignatureParameters.setSignatureIdToCounterSign(signatureId) method.", exception.getMessage());

		SignedDocumentValidator validator = getValidator(signedDocument);
		counterSignatureParameters.setSignatureIdToCounterSign(validator.getSignatures().get(0).getId());
		
		ToBeSigned dataToBeCounterSigned = service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters);
		signatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(),
				counterSignatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument counterSignedSignature = service.counterSignSignature(signedDocument, counterSignatureParameters, signatureValue);
		
		// counterSignedSignature.save("target/counterSignedSignature.sce");
		
		validator = getValidator(counterSignedSignature);
		
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		
		AdvancedSignature advancedSignature = signatures.get(0);
		List<AdvancedSignature> counterSignatures = advancedSignature.getCounterSignatures();
		assertEquals(1, counterSignatures.size());
		
		AdvancedSignature counterSignature = counterSignatures.get(0);
		assertNotNull(counterSignature.getMasterSignature());
		assertEquals(0, counterSignature.getCounterSignatures().size());
		
		counterSignatureParameters.bLevel().setSigningDate(new Date());
		counterSignatureParameters.setSignatureIdToCounterSign(counterSignature.getId());
		
		dataToBeCounterSigned = service.getDataToBeCounterSigned(counterSignedSignature, counterSignatureParameters);
		signatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(),
				counterSignatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument nestedCounterSignedSignature = service.counterSignSignature(counterSignedSignature, counterSignatureParameters, signatureValue);
		
		// nestedCounterSignedSignature.save("target/nestedCounterSignature.sce");
		
		validator = getValidator(nestedCounterSignedSignature);
		
		signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		
		advancedSignature = signatures.get(0);
		counterSignatures = advancedSignature.getCounterSignatures();
		assertEquals(1, counterSignatures.size());
		
		counterSignature = counterSignatures.get(0);
		assertNotNull(counterSignature.getMasterSignature());
		assertEquals(1, counterSignature.getCounterSignatures().size());
		
		Reports reports = verify(nestedCounterSignedSignature);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		List<SignatureWrapper> signatureWrappers = diagnosticData.getSignatures();
		assertEquals(3, signatureWrappers.size());
		
		boolean rootSignatureFound = false;
		boolean counterSignatureFound = false;
		boolean nestedCounterSignatureFound = false;
		for (SignatureWrapper signatureWrapper : signatureWrappers) {
			if (!signatureWrapper.isCounterSignature()) {
				rootSignatureFound = true;
			} else if (signatureWrapper.getParent() != null && signatureWrapper.getParent().getParent() == null) {
				counterSignatureFound = true;
			} else if (signatureWrapper.getParent() != null && signatureWrapper.getParent().getParent() != null) {
				nestedCounterSignatureFound = true;
			}
		}
		assertTrue(rootSignatureFound);
		assertTrue(counterSignatureFound);
		assertTrue(nestedCounterSignatureFound);
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		for (String signatureId : signatureIdList) {
			if (!diagnosticData.getSignatureById(signatureId).isCounterSignature() && diagnosticData.isBLevelTechnicallyValid(signatureId)) {
				List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
				assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));
			}
		}
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
		return GOOD_USER;
	}

}
