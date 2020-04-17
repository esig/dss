package eu.europa.esig.dss.xades.validation.dss1334;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

public class DSS1468Test extends AbstractXAdESTestValidation {

	private static final DSSDocument ORIGINAL_FILE = new FileDocument("src/test/resources/validation/dss1334/simple-test.xml");

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		ORIGINAL_FILE.setName(null);
		return Collections.singletonList(ORIGINAL_FILE);
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		// not valid : reference with empty URI -> not detached signature
		assertFalse(signature.isBLevelTechnicallyValid());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		// reference is not valid
	}

}
