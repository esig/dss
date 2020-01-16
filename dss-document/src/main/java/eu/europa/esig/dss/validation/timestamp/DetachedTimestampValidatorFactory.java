package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.DocumentValidatorFactory;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class DetachedTimestampValidatorFactory implements DocumentValidatorFactory {

	@Override
	public boolean isSupported(DSSDocument document) {
		DetachedTimestampValidator validator = new DetachedTimestampValidator();
		return validator.isSupported(document);
	}

	@Override
	public SignedDocumentValidator create(DSSDocument document) {
		return new DetachedTimestampValidator(document);
	}

}
