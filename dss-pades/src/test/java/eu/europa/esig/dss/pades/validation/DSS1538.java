package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1538 {

	@Test
	public void test() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/validation/encrypted.pdf"));

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());

		List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
		assertEquals(1, digestMatchers.size());

		XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
		assertEquals(DigestMatcherType.MESSAGE_DIGEST, xmlDigestMatcher.getType());
		assertTrue(xmlDigestMatcher.isDataFound());
		assertTrue(xmlDigestMatcher.isDataIntact());
	}

}
