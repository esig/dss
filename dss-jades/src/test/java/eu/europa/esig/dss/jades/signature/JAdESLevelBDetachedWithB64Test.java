package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.JWSConverter;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class JAdESLevelBDetachedWithB64Test extends AbstractJAdESTestSignature {
	
	private static final String ORIGINAL_STRING = "Hello\nWorld!";

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private DSSDocument documentToSign;
	private JAdESSignatureParameters signatureParameters;

	@BeforeEach
	public void init() {
		service = new JAdESService(getCompleteCertificateVerifier());
		documentToSign = new InMemoryDocument(ORIGINAL_STRING.getBytes(), "helloWorld");
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		
		signatureParameters.setBase64UrlEncodedPayload(false);
		signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI);
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Collections.singletonList(documentToSign);
	}
	
	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		
		String signatureString = new String(byteArray);
		assertFalse(signatureString.contains(ORIGINAL_STRING));

		InMemoryDocument compactSignature = new InMemoryDocument(byteArray);
		JWSCompactSerializationParser parser = new JWSCompactSerializationParser(compactSignature);
		JWS jws = parser.parse();
		assertNotNull(jws);

		DSSDocument converted = JWSConverter.fromJWSCompactToJSONFlattenedSerialization(compactSignature);
		assertNotNull(converted);
		assertNotNull(converted.getMimeType());
		assertNotNull(converted.getName());

		verify(converted);

		converted = JWSConverter.fromJWSCompactToJSONSerialization(compactSignature);
		assertNotNull(converted);
		assertNotNull(converted.getMimeType());
		assertNotNull(converted.getName());

		verify(converted);
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
