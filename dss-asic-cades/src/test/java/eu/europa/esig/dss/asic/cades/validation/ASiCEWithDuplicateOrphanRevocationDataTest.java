package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class ASiCEWithDuplicateOrphanRevocationDataTest extends AbstractASiCWithCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/cades-duplicate-orphan-revocation.asice");
	}
	
	@Override
	protected void checkNoDuplicateCompleteRevocationData(FoundRevocationsProxy foundRevocations) {
		super.checkNoDuplicateCompleteRevocationData(foundRevocations);
		
		List<String> revocIds = new ArrayList<>();
		for (RevocationWrapper revocationWrapper : foundRevocations.getRelatedRevocationData()) {
			assertFalse(revocIds.contains(revocationWrapper.getId()));
			revocIds.add(revocationWrapper.getId());
		}
		for (OrphanRevocationWrapper revocationWrapper : foundRevocations.getOrphanRevocationData()) {
			assertFalse(revocIds.contains(revocationWrapper.getId()));
			revocIds.add(revocationWrapper.getId());
		}
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(1, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(1, diagnosticData.getAllOrphanRevocationObjects().size());
		assertEquals(1, diagnosticData.getAllOrphanRevocationReferences().size());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SignatureLevel.CAdES_101733_C, signatureWrapper.getSignatureFormat());
	}

}
