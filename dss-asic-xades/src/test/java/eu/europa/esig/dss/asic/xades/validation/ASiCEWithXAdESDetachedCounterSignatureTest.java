package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class ASiCEWithXAdESDetachedCounterSignatureTest extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/detached-counter-signature.asice");
	}

	@Override
	protected void checkStructureValidation(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertTrue(signatureWrapper.getStructuralValidationMessage().contains("is not a valid value for 'NCName'"));
		}
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		// skip check (custom type)
	}

}
