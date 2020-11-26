package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSConverter;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class JAdESMultipleNestedCounterSignaturesTest extends AbstractJAdESTestValidation {

	private String signingAlias;

	@Test
	public void test() throws Exception {
		DSSDocument doc = new FileDocument(new File("src/test/resources/sample.json"));

		JAdESService service = new JAdESService(getCompleteCertificateVerifier());

		signingAlias = GOOD_USER;

		JAdESSignatureParameters parameters = new JAdESSignatureParameters();
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		parameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

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

		JAdESCounterSignatureParameters counterSignatureParameters = new JAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);
		counterSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
		counterSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		counterSignatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

		ToBeSigned dataToBeCounterSigned = service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters);
		SignatureValue counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument counterSignedDocument = service.counterSignSignature(signedDocument, counterSignatureParameters, counterSignatureValue);

		// 2nd counter-signature (on main signature)
		signingAlias = GOOD_USER_WITH_PSEUDO;

		counterSignatureParameters = new JAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);
		counterSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA384);
		counterSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		counterSignatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

		dataToBeCounterSigned = service.getDataToBeCounterSigned(counterSignedDocument, counterSignatureParameters);
		counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument secondCounterSignedDocument = service.counterSignSignature(counterSignedDocument, counterSignatureParameters, counterSignatureValue);
		
		// secondCounterSignedDocument.save("target/secondCounterSignedDocument.json");

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

		// 3rd counter-signature (on 1st counter-signature)
		signingAlias = GOOD_USER_WITH_CRL_AND_OCSP;

		counterSignatureParameters = new JAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureIdToCounterSign(firstCounterSignatureId);
		counterSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		counterSignatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

		dataToBeCounterSigned = service.getDataToBeCounterSigned(secondCounterSignedDocument, counterSignatureParameters);
		counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument thirdCounterSignedDocument = service.counterSignSignature(secondCounterSignedDocument, counterSignatureParameters, counterSignatureValue);

		// thirdCounterSignedDocument.save("target/thirdCounterSignedDocument.json");
		
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

		final JAdESCounterSignatureParameters newCounterSignatureParameters = new JAdESCounterSignatureParameters();
		newCounterSignatureParameters.setSigningCertificate(getSigningCert());
		newCounterSignatureParameters.setCertificateChain(getCertificateChain());
		newCounterSignatureParameters.setSignatureIdToCounterSign(secondCounterSignatureId);
		newCounterSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		newCounterSignatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
		
		Exception exception = assertThrows(DSSException.class, () -> service.getDataToBeCounterSigned(secondCounterSignedDocument, newCounterSignatureParameters));
		assertEquals("Unable to extend a Compact JAdES Signature with id '" + secondCounterSignatureId + "'", exception.getMessage());

		DSSDocument clearEtsiUIncorporation = JWSConverter.fromEtsiUWithBase64UrlToClearJsonIncorporation(thirdCounterSignedDocument);
		verify(clearEtsiUIncorporation);
		
		validator = getValidator(clearEtsiUIncorporation);
		signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		mainSignature = signatures.iterator().next();
		assertEquals(mainSignatureId, mainSignature.getId());
		counterSignatures = mainSignature.getCounterSignatures();
		assertEquals(2, counterSignatures.size());
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