package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1562Test extends PKIFactoryAccess {
	
	@Test
	public void test() {
		
		DSSDocument doc = new FileDocument("src/test/resources/validation/xades-detached-with-object-type-ref.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		DSSDocument detachedContent = new FileDocument("src/test/resources/sample.png");
		validator.setDetachedContents(Arrays.asList(detachedContent));
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		assertNotNull(signature.getDigestMatchers());
		assertEquals(2, signature.getDigestMatchers().size());
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			assertNotNull(digestMatcher.getType());
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
}
