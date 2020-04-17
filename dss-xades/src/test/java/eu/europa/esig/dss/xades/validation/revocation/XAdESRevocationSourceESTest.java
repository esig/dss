package eu.europa.esig.dss.xades.validation.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrappper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

public class XAdESRevocationSourceESTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-X-ES-100.xml");
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(4, signature.foundRevocations().getRelatedRevocationData().size());
		assertEquals(4, signature.foundRevocations().getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByRefOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
		int ocspResponses = 0;
		List<String> revocationDigests = new ArrayList<>();
		for (RelatedRevocationWrapper revocation : signature.foundRevocations().getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS)) {
			for (RevocationRefWrappper revocationRef : revocation.getReferences()) {
				assertNotNull(revocationRef.getDigestAlgoAndValue());
				assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
				assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
				assertNotNull(revocationRef.getOrigins());
				if (revocationRef.getProductionTime() != null) {
					assertTrue(Utils.isStringNotEmpty(revocationRef.getResponderIdName()) || Utils.isArrayNotEmpty(revocationRef.getResponderIdKey()));
					ocspResponses++;
				}
				String base64 = Utils.toBase64(revocationRef.getDigestAlgoAndValue().getDigestValue());
				assertFalse(revocationDigests.contains(base64));
				revocationDigests.add(base64);
			}
		}
		assertEquals(signature.foundRevocations().getRelatedRevocationsByType(RevocationType.OCSP).size(), ocspResponses);
	}

}
