package eu.europa.esig.dss.validation;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;

public class MockDocumentValidator extends SignedDocumentValidator {

	public MockDocumentValidator() {
		super(null);
	}

	protected MockDocumentValidator(SignatureScopeFinder signatureScopeFinder) {
		super(signatureScopeFinder);
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		return Collections.emptyList();
	}

	@Override
	public DSSDocument getOriginalDocument(String signatureId) throws DSSException {
		return null;
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return true;
	}

}
