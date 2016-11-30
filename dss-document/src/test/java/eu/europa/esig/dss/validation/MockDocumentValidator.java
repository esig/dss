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
	public List<DSSDocument> getOriginalDocuments(String signatureId) throws DSSException {
		return Collections.emptyList();
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return true;
	}

}
