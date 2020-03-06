package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XAdESDoubleSignedDifferentOCSPTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		// Strange case with 2 signatures from the same certificate and 2 OCSP responses
		// for the same intermediate CA. Second OCSP Response is not processed
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument("src/test/resources/validation/doubleSignedTest.xml"));
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertTrue(Utils.isCollectionNotEmpty(signatureIdList));
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
		}
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		SignatureWrapper signatureWrapper = signatures.get(0);
		
		assertEquals(1, signatureWrapper.foundRevocations().getRelatedRevocationData().size());
		assertEquals(1, signatureWrapper.foundRevocations().getOrphanRevocationData().size());
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
	
	@Override
	protected String getSigningAlias() {
		// TODO Auto-generated method stub
		return null;
	}

}
