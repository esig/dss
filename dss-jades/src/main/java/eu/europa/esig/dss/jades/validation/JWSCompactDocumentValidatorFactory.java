package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.DocumentValidatorFactory;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class JWSCompactDocumentValidatorFactory implements DocumentValidatorFactory{

	@Override
	public boolean isSupported(DSSDocument document) {
		JWSCompactDocumentValidator validator = new JWSCompactDocumentValidator();
		return validator.isSupported(document);
	}

	@Override
	public SignedDocumentValidator create(DSSDocument document) {
		return new JWSCompactDocumentValidator(document);
	}

}
