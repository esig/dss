package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

//@formatter:off
/**
 * {
 * 
 * "payload":"payload contents",
 * 
 * "signatures":[
 * 
 * {"protected":"integrity-protected header 1 contents",
 * "header":non-integrity-protected header 1 contents, 
 * "signature":"signature 1 contents"},
 * 
 * ...
 * 
 * {"protected":"integrity-protected header N contents",
 * "header":non-integrity-protected header N contents, 
 * "signature":"signature N contents"}
 * 
 * ]
 * 
 * }
 */
//@formatter:on
public class JWSSerializationDocumentValidator extends AbstractJWSDocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(JWSSerializationDocumentValidator.class);

	/** A list of signatures */
	private List<AdvancedSignature> signatures;

	/**
	 * Empty constructor
	 */
	public JWSSerializationDocumentValidator() {
	}

	/**
	 * Default constructor
	 *
	 * @param document {@link DSSDocument} to validate
	 */
	public JWSSerializationDocumentValidator(DSSDocument document) {
		super(document);
	}

	@Override
	public boolean isSupported(DSSDocument document) {
		JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(document);
		return jwsJsonSerializationParser.isSupported();
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		if (signatures == null) {
			signatures = new ArrayList<>();
			
			JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(document);
			JWSJsonSerializationObject jwsJsonSerializationObject = jwsJsonSerializationParser.parse();
			
			List<JWS> foundSignatures = jwsJsonSerializationObject.getSignatures();
			LOG.info("{} signature(s) found", Utils.collectionSize(foundSignatures));
			for (JWS jws : foundSignatures) {
				JAdESSignature jadesSignature = new JAdESSignature(jws);
				jadesSignature.setSignatureFilename(document.getName());
				jadesSignature.setSigningCertificateSource(signingCertificateSource);
				jadesSignature.setDetachedContents(detachedContents);
				jadesSignature.prepareOfflineCertificateVerifier(certificateVerifier);
				signatures.add(jadesSignature);
			}
		}
		return signatures;
	}

}
