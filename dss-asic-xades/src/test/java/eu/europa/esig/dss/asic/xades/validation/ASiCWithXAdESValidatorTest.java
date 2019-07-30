package eu.europa.esig.dss.asic.xades.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.AbstractTestValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class ASiCWithXAdESValidatorTest extends AbstractTestValidator {

	@Override
	protected SignedDocumentValidator initEmptyValidator() {
		return new ASiCContainerWithXAdESValidator();
	}

	@Override
	protected SignedDocumentValidator initValidator(DSSDocument document) {
		return new ASiCContainerWithXAdESValidator(document);
	}

	@Override
	protected List<DSSDocument> getValidDocuments() {
		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new FileDocument("src/test/resources/validation/onefile-ok.asice"));
		documents.add(new FileDocument("src/test/resources/validation/onefile-ok.asics"));
		documents.add(new FileDocument("src/test/resources/validation/multifiles-ok.asice"));
		documents.add(new FileDocument("src/test/resources/validation/multifiles-ok.asics"));
		documents.add(new FileDocument("src/test/resources/validation/libreoffice.ods"));
		documents.add(new FileDocument("src/test/resources/validation/libreoffice.odt"));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new FileDocument("src/test/resources/validation/malformed-container.asice");
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new FileDocument("src/test/resources/manifest-sample.xml");
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		return new FileDocument("src/test/resources/validation/no-signature.asics");
	}

}