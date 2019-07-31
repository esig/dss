package eu.europa.esig.dss.asic.cades.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.AbstractTestValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class ASiCWithCAdESValidatorTest extends AbstractTestValidator {

	@Override
	protected SignedDocumentValidator initEmptyValidator() {
		return new ASiCContainerWithCAdESValidator();
	}

	@Override
	protected SignedDocumentValidator initValidator(DSSDocument document) {
		return new ASiCContainerWithCAdESValidator(document);
	}

	@Override
	protected List<DSSDocument> getValidDocuments() {
		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new FileDocument("src/test/resources/validation/onefile-ok.asice"));
		documents.add(new FileDocument("src/test/resources/validation/onefile-ok.asics"));
		documents.add(new FileDocument("src/test/resources/validation/multifiles-ok.asice"));
		documents.add(new FileDocument("src/test/resources/validation/multifiles-ok.asics"));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new FileDocument("src/test/resources/validation/malformed-container.asics");
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new FileDocument("src/test/resources/signable/test.txt");
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		// not applicable
		return null;
	}

}
