package eu.europa.esig.dss.jades.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class JWSCompactDocumentValidator extends AbstractJWSDocumentValidator {
	
	private List<AdvancedSignature> signatures;

	public JWSCompactDocumentValidator() {
	}

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
		if (signatures == null) {
			signatures = new ArrayList<>();
			JWSCompactSerializationParser parser = new JWSCompactSerializationParser(document);
			JAdESSignature jadesSignature = new JAdESSignature(parser.parse());
			jadesSignature.setSigningCertificateSource(signingCertificateSource);
			jadesSignature.setDetachedContents(detachedContents);
			jadesSignature.prepareOfflineCertificateVerifier(certificateVerifier);
			signatures.add(jadesSignature);
		}
		return signatures;
	}

}
