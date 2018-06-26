package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DSS1334Test {

	@Test
	public void test1a() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");

		assertCryptoValid(doc);
	}

	@Test
	public void test1b() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");
		doc.setName(null);
		doc.setMimeType(null);

		assertCryptoValid(doc);
	}

	@Test
	public void test1c() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");
		doc.setName("");
		doc.setMimeType(null);

		assertCryptoValid(doc);
	}

	@Test
	public void test2() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/simple-test-signed-xades-baseline-b.xml");

		assertCryptoValid(doc);
	}

	@Test
	public void test3() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/simple-test.signed-only-detached-LuxTrustCA3.xml");
		assertCryptoValid(doc);
	}

	private void assertCryptoValid(DSSDocument doc) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		validator.setDetachedContents(
				Arrays.<DSSDocument>asList(new FileDocument("src/test/resources/validation/dss1334/simple-test.xml")));

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}
	}

}
