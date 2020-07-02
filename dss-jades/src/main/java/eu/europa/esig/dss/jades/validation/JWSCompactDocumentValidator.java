package eu.europa.esig.dss.jades.validation;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class JWSCompactDocumentValidator extends AbstractJWSDocumentValidator {

	private final static int NUMBER_DOTS = 2;
	
	private List<AdvancedSignature> signatures;

	public JWSCompactDocumentValidator() {
	}

	public JWSCompactDocumentValidator(DSSDocument document) {
		super(document);
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {

		int separatorCounter = 0;
		try (InputStream is = dssDocument.openStream()) {
			int b = -1;
			while ((b = is.read()) != -1) {
				byte currentByte = (byte) b;
				if (!JAdESUtils.isUrlSafe(currentByte)) {

					if (currentByte == '.') {
						separatorCounter++;
						if (separatorCounter > NUMBER_DOTS) {
							return false;
						}
					} else {
						return false;
					}
				}
			}

			if (separatorCounter != NUMBER_DOTS) {
				return false;
			}

		} catch (IOException e) {
			throw new DSSException(String.format("Cannot read the document. Reason : %s", e.getMessage()), e);
		}
		return true;
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		if (signatures == null) {
			signatures = new ArrayList<>();
			JWSCompactSerializationParser parser = new JWSCompactSerializationParser(document);
			JAdESSignature jadesSignature = new JAdESSignature(parser.parse());
			jadesSignature.setProvidedSigningCertificateToken(providedSigningCertificateToken);
			jadesSignature.setDetachedContents(detachedContents);
			signatures.add(jadesSignature);
		}
		return signatures;
	}

}
