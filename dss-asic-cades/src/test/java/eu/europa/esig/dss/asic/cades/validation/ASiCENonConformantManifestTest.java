package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class ASiCENonConformantManifestTest extends AbstractASiCWithCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/nonConformantManifest.asice");
	}
	
	@Override
	protected void checkValidationContext(SignedDocumentValidator validator) {
		super.checkValidationContext(validator);
		
		ASiCContainerWithCAdESValidator asicValidator = (ASiCContainerWithCAdESValidator) validator;
		
		List<DSSDocument> manifestDocuments = asicValidator.getManifestDocuments();
		List<ManifestFile> manifestFiles = asicValidator.getManifestFiles();
		assertEquals(manifestDocuments.size(), manifestFiles.size());
		assertEquals(1, manifestFiles.size());
		
		ManifestFile manifestFile = manifestFiles.get(0);
		assertNotNull(manifestFile.getFilename());
		assertNotNull(manifestFile.getSignatureFilename());
		assertTrue(Utils.isCollectionEmpty(manifestFile.getEntries()));
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionEmpty(validator.getOriginalDocuments(signatures.get(0))));
	}

}
