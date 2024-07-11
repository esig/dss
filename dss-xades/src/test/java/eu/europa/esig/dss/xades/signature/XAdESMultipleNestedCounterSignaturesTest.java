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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class XAdESMultipleNestedCounterSignaturesTest extends AbstractPkiFactoryTestValidation {

	private String signingAlias;

	@Test
	void test() throws Exception {
		DSSDocument doc = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		signingAlias = GOOD_USER;

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		ToBeSigned dataToSign = service.getDataToSign(doc, parameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(doc, parameters, signatureValue);

		verify(signedDocument);

		SignedDocumentValidator validator = getValidator(signedDocument);
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		String mainSignatureId = signatures.iterator().next().getId();

		// 1st counter-signature (on main signature)
		signingAlias = EE_GOOD_USER;

		XAdESCounterSignatureParameters counterSignatureParameters = new XAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);
		counterSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
		counterSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		ToBeSigned dataToBeCounterSigned = service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters);
		SignatureValue counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument counterSignedDocument = service.counterSignSignature(signedDocument, counterSignatureParameters, counterSignatureValue);

		// 2nd counter-signature (on main signature)
		signingAlias = GOOD_USER_WITH_PSEUDO;

		counterSignatureParameters = new XAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);
		counterSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA384);
		counterSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		dataToBeCounterSigned = service.getDataToBeCounterSigned(counterSignedDocument, counterSignatureParameters);
		counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument secondCounterSignedDocument = service.counterSignSignature(counterSignedDocument, counterSignatureParameters, counterSignatureValue);
		
		// secondCounterSignedDocument.save("target/secondCounterSignedDocument.xml");

		verify(secondCounterSignedDocument);

		validator = getValidator(secondCounterSignedDocument);
		signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		AdvancedSignature mainSignature = signatures.iterator().next();
		assertEquals(mainSignatureId, mainSignature.getId());
		List<AdvancedSignature> counterSignatures = mainSignature.getCounterSignatures();
		assertEquals(2, counterSignatures.size());
		for (AdvancedSignature advancedSignature : counterSignatures) {
			assertNotNull(advancedSignature.getMasterSignature());
			assertEquals(mainSignatureId, advancedSignature.getMasterSignature().getId());
		}
		String firstCounterSignatureId = counterSignatures.get(0).getId();

		// 3rd counter-signature (on 1st counter-signature)
		signingAlias = GOOD_USER_WITH_CRL_AND_OCSP;

		counterSignatureParameters = new XAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureIdToCounterSign(firstCounterSignatureId);
		counterSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		dataToBeCounterSigned = service.getDataToBeCounterSigned(secondCounterSignedDocument, counterSignatureParameters);
		counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument thirdCounterSignedDocument = service.counterSignSignature(secondCounterSignedDocument, counterSignatureParameters, counterSignatureValue);

		// thirdCounterSignedDocument.save("target/thirdCounterSignedDocument.xml");
		
		verify(thirdCounterSignedDocument);

		validator = getValidator(thirdCounterSignedDocument);
		signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		mainSignature = signatures.iterator().next();
		assertEquals(mainSignatureId, mainSignature.getId());
		counterSignatures = mainSignature.getCounterSignatures();
		assertEquals(2, counterSignatures.size());
		for (AdvancedSignature counterSignatureLevel1 : counterSignatures) {
			assertNotNull(counterSignatureLevel1.getMasterSignature());
			assertEquals(mainSignatureId, counterSignatureLevel1.getMasterSignature().getId());
			if (counterSignatureLevel1.getId().equals(firstCounterSignatureId)) {
				List<AdvancedSignature> counterSignaturesLevel2 = counterSignatureLevel1.getCounterSignatures();
				assertEquals(1, counterSignaturesLevel2.size());
				assertEquals(firstCounterSignatureId, counterSignaturesLevel2.get(0).getMasterSignature().getId());
			}
		}

	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

}