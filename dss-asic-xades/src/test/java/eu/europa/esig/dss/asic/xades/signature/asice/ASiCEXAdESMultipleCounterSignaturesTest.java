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
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEXAdESMultipleCounterSignaturesTest extends AbstractASiCWithXAdESTestValidation {

	private String signingAlias;

	@Test
	public void test() throws Exception {
		List<DSSDocument> documentToSigns = new ArrayList<>();
		documentToSigns.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT));
		documentToSigns.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeTypeEnum.TEXT));

		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());

		signingAlias = GOOD_USER;

		ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		ToBeSigned dataToSign = service.getDataToSign(documentToSigns, parameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSigns, parameters, signatureValue);

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
		
		// secondCounterSignedDocument.save("target/secondCounterSignedDocument.sce");

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
		String secondCounterSignatureId = counterSignatures.get(1).getId();
		assertNotEquals(firstCounterSignatureId, secondCounterSignatureId);

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

		// thirdCounterSignedDocument.save("target/thirdCounterSignedDocument.sce");
		
		Reports reports = verify(thirdCounterSignedDocument);

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
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(4, diagnosticData.getOriginalSignerDocuments().size());
		
		for (DSSDocument originalDoc : documentToSigns) {
			boolean found = false;
			for (SignerDataWrapper signerData : diagnosticData.getOriginalSignerDocuments()) {
				if (originalDoc.getName().equals(signerData.getReferencedName())) {
					found = true;
					break;
				}
			}
			assertTrue(found);
		}
		
		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		assertNotNull(containerInfo);
		assertEquals(2, containerInfo.getContentFiles().size());

	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}
	
	@Override
	public void validate() {
		// do nothing
	}

	@Override
	protected DSSDocument getSignedDocument() {
		// TODO Auto-generated method stub
		return null;
	}

}
