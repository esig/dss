package eu.europa.esig.dss.cades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class CounterSignaturesTest extends AbstractPkiFactoryTestValidation<CAdESSignatureParameters, CAdESTimestampParameters> {

	private String signingAlias;

	@Test
	public void test() {
		DSSDocument doc = new InMemoryDocument("Hello".getBytes());

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());

		signingAlias = GOOD_USER;

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

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

		CAdESCounterSignatureParameters counterSignatureParameters = new CAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);
		counterSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

		ToBeSigned dataToBeCounterSigned = service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters);
		SignatureValue counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument counterSignedDocument = service.counterSignSignature(signedDocument, counterSignatureParameters, counterSignatureValue);

		// 2nd counter-signature (on main signature)
		signingAlias = GOOD_USER_WITH_PSEUDO;

		counterSignatureParameters = new CAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureIdToCounterSign(mainSignatureId);
		counterSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA384);

		dataToBeCounterSigned = service.getDataToBeCounterSigned(counterSignedDocument, counterSignatureParameters);
		counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument secondCounterSignedDocument = service.counterSignSignature(counterSignedDocument, counterSignatureParameters, counterSignatureValue);

		verify(secondCounterSignedDocument);

		validator = getValidator(signedDocument);
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

		counterSignatureParameters = new CAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureIdToCounterSign(firstCounterSignatureId);

		dataToBeCounterSigned = service.getDataToBeCounterSigned(secondCounterSignedDocument, counterSignatureParameters);
		counterSignatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument thirdCounterSignedDocument = service.counterSignSignature(secondCounterSignedDocument, counterSignatureParameters, counterSignatureValue);

		verify(thirdCounterSignedDocument);

		validator = getValidator(signedDocument);
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
