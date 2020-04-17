package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class XAdESDoubleSignedDifferentOCSPTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/doubleSignedTest.xml");
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		SignatureWrapper signatureWrapper = signatures.get(0);
		
		assertEquals(2, signatureWrapper.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, signatureWrapper.foundRevocations().getOrphanRevocationData().size());
		assertEquals(0, signatureWrapper.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals(0, signatureWrapper.foundRevocations().getOrphanRevocationRefs().size());
		
		List<RelatedCertificateWrapper> foundCertificatesByLocation = signatureWrapper.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES);
		assertNotNull(foundCertificatesByLocation);
		assertEquals(2, foundCertificatesByLocation.size());
		
		SignatureWrapper signature2Wrapper = signatures.get(1);
		assertEquals(2, signature2Wrapper.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, signature2Wrapper.foundRevocations().getOrphanRevocationData().size());
		assertEquals(2, signature2Wrapper.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals(0, signature2Wrapper.foundRevocations().getOrphanRevocationRefs().size());
	}

}
