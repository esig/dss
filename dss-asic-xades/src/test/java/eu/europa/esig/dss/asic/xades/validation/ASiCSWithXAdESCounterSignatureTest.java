package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class ASiCSWithXAdESCounterSignatureTest extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/containerWithCounterSig.asics");
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		int counterSigCounter = 0;
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.isCounterSignature()) {
				assertTrue(signatureWrapper.isBLevelTechnicallyValid());
				
				++counterSigCounter;
			}
		}
		assertEquals(1, counterSigCounter);
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		super.verifyOriginalDocuments(validator, diagnosticData);
		
		for (AdvancedSignature advancedSignature : validator.getSignatures()) {
			assertEquals(1, validator.getOriginalDocuments(advancedSignature).size());
		}
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertEquals(1, validator.getOriginalDocuments(signatureWrapper.getId()).size());
		}
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertTrue(signatureWrapper.isAttributePresent());
			assertTrue(signatureWrapper.isDigestValuePresent());
			assertTrue(signatureWrapper.isDigestValueMatch());
		}
	}

}
