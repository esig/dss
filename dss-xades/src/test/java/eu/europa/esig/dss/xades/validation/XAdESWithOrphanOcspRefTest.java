package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.OrphanTokenWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrappper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class XAdESWithOrphanOcspRefTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/sig-with-orphan-ocsp-ref.xml");
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<OrphanRevocationWrapper> orphanRevocationData = signatureWrapper.foundRevocations().getOrphanRevocationData();
		assertEquals(3, orphanRevocationData.size());
		
		List<OrphanRevocationWrapper> ocspOrphanRevocations = signatureWrapper.foundRevocations().getOrphanRevocationsByType(RevocationType.OCSP);
		assertEquals(2, ocspOrphanRevocations.size());
		
		int containsDigest = 0;
		String noDigestOcspRefId = null;
		for (OrphanRevocationWrapper orphanRevocationWrapper : ocspOrphanRevocations) {
			List<RevocationRefWrappper> references = orphanRevocationWrapper.getReferences();
			assertEquals(1, references.size());
			
			RevocationRefWrappper revocationRefWrappper = references.get(0);
			XmlDigestAlgoAndValue digestAlgoAndValue = revocationRefWrappper.getDigestAlgoAndValue();
			if (digestAlgoAndValue != null) {
				++containsDigest;
			} else {
				assertNotNull(revocationRefWrappper.getProductionTime());
				assertNotNull(revocationRefWrappper.getResponderIdName());
				noDigestOcspRefId = orphanRevocationWrapper.getId();
			}
		}
		assertEquals(1, containsDigest);
		assertNotNull(noDigestOcspRefId);
		
		List<RevocationRefWrappper> orphanRevocationRefs = signatureWrapper.foundRevocations().getOrphanRevocationRefs();
		assertEquals(3, orphanRevocationRefs.size());
		
		List<OrphanRevocationWrapper> allOrphanRevocationObjects = diagnosticData.getAllOrphanRevocationObjects();
		assertEquals(1, allOrphanRevocationObjects.size());
		
		OrphanRevocationWrapper orphanRevocationWrapper = allOrphanRevocationObjects.get(0);
		assertEquals(noDigestOcspRefId, orphanRevocationWrapper.getId());
		
		List<OrphanTokenWrapper> allOrphanRevocationReferences = diagnosticData.getAllOrphanRevocationReferences();
		assertEquals(2, allOrphanRevocationReferences.size());
		
	}

}
