package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class JAdESFlattenedParallelSignatureTest extends AbstractJAdESTestValidation {
	
	private DSSDocument toBeSigned;
	private JAdESService service;
	
	@BeforeEach
	public void init() {
		toBeSigned = new FileDocument(new File("src/test/resources/sample.json"));
		service = new JAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected DSSDocument getSignedDocument() {
		DSSDocument signedDocument = getFlattenedSignature(toBeSigned);
		// signedDocument.save("target/" + "signedDocument.json");

		DSSDocument doubleSignedDocument = getCompleteSerializationSignature(signedDocument);
		// doubleSignedDocument.save("target/" + "doubleSignedDocument.json");
		
		assertTrue(DSSJsonUtils.isJsonDocument(doubleSignedDocument));
		try {
			Map<String, Object> rootStructure = JsonUtil.parseJson(new String(DSSUtils.toByteArray(doubleSignedDocument)));
			
			String payload = (String) rootStructure.get(JWSConstants.PAYLOAD);
			assertNotNull(payload);
			assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(payload)));

			List<Map<String, Object>> signaturesList = (List<Map<String, Object>>) rootStructure.get(JWSConstants.SIGNATURES);
			assertTrue(Utils.isCollectionNotEmpty(signaturesList));
			assertEquals(2, signaturesList.size());
			
			for (Map<String, Object> signature : signaturesList) {
				String header = (String) signature.get(JWSConstants.PROTECTED);
				assertNotNull(header);
				assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(header)));
				
				String signatureValueBase64Url = (String) signature.get(JWSConstants.SIGNATURE);
				assertNotNull(signatureValueBase64Url);
				assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(signatureValueBase64Url)));
			}
			
		} catch (JoseException e) {
			fail("Unable to parse the signed file : " + e.getMessage());
		}
		 
		return doubleSignedDocument;
	}
	
	@Test
	public void parallelSignFlattenedTest() {
		DSSDocument serializationSignature = getCompleteSerializationSignature(toBeSigned);
		Exception exception = assertThrows(DSSException.class, () -> getFlattenedSignature(serializationSignature));
		assertEquals("The 'FLATTENED_JSON_SERIALIZATION' type is not supported for a parallel signing!", exception.getMessage());
	}
	
	@Test
	public void twiceSignFlattenedTest() {
		DSSDocument flattenedSignature = getFlattenedSignature(toBeSigned);
		Exception exception = assertThrows(DSSException.class, () -> getFlattenedSignature(flattenedSignature));
		assertEquals("The 'FLATTENED_JSON_SERIALIZATION' type is not supported for a parallel signing!", exception.getMessage());
	}
	
	private DSSDocument getFlattenedSignature(DSSDocument documentToSign) {
		JAdESSignatureParameters params = new JAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentToSign, params, signatureValue);
	}
	
	private DSSDocument getCompleteSerializationSignature(DSSDocument documentToSign) {
		JAdESSignatureParameters params = new JAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentToSign, params, signatureValue);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
