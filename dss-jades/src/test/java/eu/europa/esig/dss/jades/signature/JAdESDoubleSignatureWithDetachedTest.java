package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;

public class JAdESDoubleSignatureWithDetachedTest extends AbstractJAdESTestValidation {
	
	private List<DSSDocument> documentsToSign;
	private JAdESService service;
	private JAdESSignatureParameters signatureParameters;
	
	private Calendar calendar;

	@BeforeEach
	public void init() {
		documentsToSign = Arrays.asList(new FileDocument("src/test/resources/sample.json"), new FileDocument("src/test/resources/sample.png"),
				new InMemoryDocument("Hello World!".getBytes(), "helloWorld")) ;
		
		calendar = Calendar.getInstance();

		service = new JAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(calendar.getTime());
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		signatureParameters.setSigningCertificate(getSigningCert());
	}

	@Override
	protected DSSDocument getSignedDocument() {
		DSSDocument signedDocument = sign(documentsToSign, signatureParameters);
		// signedDocument.save("target/" + "signedDocument.json");
		
		// avoid same second signature creation
		calendar.add(Calendar.SECOND, 1);
		
		signatureParameters.bLevel().setSigningDate(calendar.getTime());
		signatureParameters.setDetachedContents(documentsToSign);
		DSSDocument doubleSignedDocument = sign(Collections.singletonList(signedDocument), signatureParameters);
		// doubleSignedDocument.save("target/" + "doubleSignedDocument.json");
		
		assertTrue(JAdESUtils.isJsonDocument(doubleSignedDocument));
		 
		return doubleSignedDocument;
	}
	
	private DSSDocument sign(List<DSSDocument> documentsToSign, JAdESSignatureParameters signatureParameters) {
		ToBeSigned dataToSign = service.getDataToSign(documentsToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentsToSign, signatureParameters, signatureValue);
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return documentsToSign;
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		super.checkSignatureIdentifier(diagnosticData);

		assertEquals(2, diagnosticData.getSignatureIdList().size());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			int signedDocumentsCounter = 0;
			
			List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
			assertEquals(4, digestMatchers.size());
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				if (DigestMatcherType.SIG_D_ENTRY.equals(digestMatcher.getType())) {
					++signedDocumentsCounter;
				}
			}
			
			assertEquals(documentsToSign.size(), signedDocumentsCounter);
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
