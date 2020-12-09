package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.DocumentValidatorFactory;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/**
 * Loads the relevant Validator to process a given JAdES signature
 */
public class JAdESDocumentValidatorFactory implements DocumentValidatorFactory {

	@Override
	public boolean isSupported(DSSDocument document) {
		JWSCompactDocumentValidator compactValidator = new JWSCompactDocumentValidator();
		if (compactValidator.isSupported(document)) {
			return true;
		}

		JWSSerializationDocumentValidator serializationValidator = new JWSSerializationDocumentValidator();
		if (serializationValidator.isSupported(document)) {
			return true;
		}

		return false;
	}

	@Override
	public SignedDocumentValidator create(DSSDocument document) {

		JWSCompactDocumentValidator compactValidator = new JWSCompactDocumentValidator();
		if (compactValidator.isSupported(document)) {
			return new JWSCompactDocumentValidator(document);
		}

		JWSSerializationDocumentValidator serializationValidator = new JWSSerializationDocumentValidator();
		if (serializationValidator.isSupported(document)) {
			return new JWSSerializationDocumentValidator(document);
		}

		throw new IllegalArgumentException("Not supported document");
	}

}