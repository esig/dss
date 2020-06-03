package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.DocumentValidatorFactory;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class JWSSerializationDocumentValidatorFactory implements DocumentValidatorFactory{

	@Override
	public boolean isSupported(DSSDocument document) {
		JWSSerializationDocumentValidator validator = new JWSSerializationDocumentValidator();
		return validator.isSupported(document);
	}

	@Override
	public SignedDocumentValidator create(DSSDocument document) {
		return new JWSSerializationDocumentValidator(document);
	}

}
