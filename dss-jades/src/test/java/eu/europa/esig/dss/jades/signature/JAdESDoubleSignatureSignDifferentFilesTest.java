package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.utils.Utils;

public class JAdESDoubleSignatureSignDifferentFilesTest extends AbstractJAdESTestValidation {
	
	private JAdESService service;
	private JAdESSignatureParameters signatureParameters;
	
	private DSSDocument documentOne = new FileDocument("src/test/resources/sample.json");
	private DSSDocument documentTwo = new FileDocument("src/test/resources/sample.png");
	private DSSDocument documentThree = new InMemoryDocument("Hello World!".getBytes(), "helloWorld");
	
	@BeforeEach
	public void init() {
		service = new JAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH);
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		signatureParameters.setSigningCertificate(getSigningCert());
	}

	@Override
	protected DSSDocument getSignedDocument() {
		List<DSSDocument> documentsToSign = Arrays.asList(documentOne, documentTwo);
		
		DSSDocument signedDocument = sign(documentsToSign, signatureParameters);
		// signedDocument.save("target/" + "signedDocument.json");
		
		signatureParameters.setDetachedContents(Arrays.asList(documentTwo, documentThree));
		
		DSSDocument doubleSignedDocument = sign(Collections.singletonList(signedDocument), signatureParameters);
		// doubleSignedDocument.save("target/" + "doubleSignedDocument.json");
		
		assertTrue(DSSJsonUtils.isJsonDocument(doubleSignedDocument));
		 
		return doubleSignedDocument;
	}
	
	private DSSDocument sign(List<DSSDocument> documentsToSign, JAdESSignatureParameters signatureParameters) {
		ToBeSigned dataToSign = service.getDataToSign(documentsToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentsToSign, signatureParameters, signatureValue);
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(documentOne, documentTwo, documentThree);
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		super.checkSignatureIdentifier(diagnosticData);

		assertEquals(2, diagnosticData.getSignatureIdList().size());
	}

	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		SignatureWrapper signatureOne = diagnosticData.getSignatures().get(0);
		assertDocsCovered(signatureOne, true, true, false);
		
		SignatureWrapper signatureTwo = diagnosticData.getSignatures().get(1);
		assertDocsCovered(signatureTwo, false, true, true);
	}
	
	private void assertDocsCovered(SignatureWrapper signature, boolean firstDoc, boolean secondDoc, boolean thirdDoc) {
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		
		assertEquals(2, signatureScopes.size());
		
		boolean firstDocFound = false;
		boolean secondDocFound = false;
		boolean thirdDocFound = false;
		
		for (XmlSignatureScope signatureScope : signatureScopes) {
			DigestAlgorithm digestAlgorithm = signatureScope.getSignerData().getDigestAlgoAndValue().getDigestMethod();
			byte[] digestValue = signatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue();
			
			if (documentOne.getName().equals(signatureScope.getName())) {
				assertEquals(documentOne.getDigest(digestAlgorithm), Utils.toBase64(digestValue));
				firstDocFound = true;
			} else if (documentTwo.getName().equals(signatureScope.getName())) {
				assertEquals(documentTwo.getDigest(digestAlgorithm), Utils.toBase64(digestValue));
				secondDocFound = true;
			} else if (documentThree.getName().equals(signatureScope.getName())) {
				assertEquals(documentThree.getDigest(digestAlgorithm), Utils.toBase64(digestValue));
				thirdDocFound = true;
			} else {
				fail("The document with name '" + signatureScope.getName() + "' has not been defined");
			}
		}
		
		assertEquals(firstDoc, firstDocFound);
		assertEquals(secondDoc, secondDocFound);
		assertEquals(thirdDoc, thirdDocFound);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
