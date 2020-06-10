package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;

public class JAdESSerializationDoubleSignatureTest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.json"));

		JAdESService service = new JAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		JAdESSignatureParameters params = new JAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "signedDocument.json");

		params = new JAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		params.setSigningCertificate(getSigningCert());

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedDocument.json");
		 
		return doubleSignedDocument;
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		super.checkSignatureIdentifier(diagnosticData);
		
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
			assertFalse(diagnosticData.getSignatureById(signatureId).isSignatureDuplicated());
		}

		assertFalse(signatureIdList.get(0).equals(signatureIdList.get(1)));
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		assertEquals(2, diagnosticData.getSignatures().size());
		
		SignatureWrapper signatureOne = diagnosticData.getSignatures().get(0);
		SignatureWrapper signatureTwo = diagnosticData.getSignatures().get(1);
		assertFalse(Arrays.equals(signatureOne.getDigestMatchers().get(0).getDigestValue(), signatureTwo.getDigestMatchers().get(0).getDigestValue()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
