package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class ASiCSWithXAdESMultiFilesValidationTest extends AbstractASiCWithXAdESTestValidation {

	private final List<DSSDocument> EXPECTED_MULTIFILES = Arrays.<DSSDocument> asList(
			new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT),
			new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT));

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/multifiles-too-much-files.asics");
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		assertEquals(2, signatures.size());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		super.verifyOriginalDocuments(validator, diagnosticData);
		
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature advancedSignature : signatures) {
			List<DSSDocument> originalDocuments = validator.getOriginalDocuments(advancedSignature.getId());
			assertEquals(2, originalDocuments.size());
			
			for (DSSDocument dssDocument : EXPECTED_MULTIFILES) {
				String digestExpected = dssDocument.getDigest(DigestAlgorithm.SHA256);
				boolean found = false;
				for (DSSDocument retrieved : originalDocuments) {
					String digestRetrieved = retrieved.getDigest(DigestAlgorithm.SHA256);
					if (Utils.areStringsEqual(digestExpected, digestRetrieved)) {
						found = true;
					}
				}
				assertTrue(found);
			}
		}
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		List<SignatureWrapper> signatureWrappers = diagnosticData.getSignatures();
		for (SignatureWrapper signature : signatureWrappers) {
			assertNotNull(signature);
			List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
			assertNotNull(signatureScopes);
			assertEquals(3, signatureScopes.size());
			int archivedFiles = 0;
			for (XmlSignatureScope signatureScope : signatureScopes) {
				if (SignatureScopeType.ARCHIVED.equals(signatureScope.getScope())) {
					archivedFiles++;
				}
			}
			assertEquals(2, archivedFiles);
		}
	}

}
