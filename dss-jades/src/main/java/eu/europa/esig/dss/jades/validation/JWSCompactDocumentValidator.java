package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;

import java.util.Arrays;
import java.util.List;

/**
 * Validates a JWS Compact signature
 */
public class JWSCompactDocumentValidator extends AbstractJWSDocumentValidator {

	/** The JAdES Compact signature */
	private AdvancedSignature signature;

	/**
	 * Empty constructor
	 */
	public JWSCompactDocumentValidator() {
	}

	/**
	 * Default constructor
	 *
	 * @param document {@link DSSDocument} to validate
	 */
	public JWSCompactDocumentValidator(DSSDocument document) {
		super(document);
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		JWSCompactSerializationParser parser = new JWSCompactSerializationParser(dssDocument);
		return parser.isSupported();
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		if (signature == null) {
			JWSCompactSerializationParser parser = new JWSCompactSerializationParser(document);
			JAdESSignature jadesSignature = new JAdESSignature(parser.parse());
			jadesSignature.setSignatureFilename(document.getName());
			jadesSignature.setSigningCertificateSource(signingCertificateSource);
			jadesSignature.setDetachedContents(detachedContents);
			jadesSignature.prepareOfflineCertificateVerifier(certificateVerifier);
			signature = jadesSignature;
		}
		return Arrays.asList(signature);
	}

}
