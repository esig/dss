package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DSS1334Test {

	private static final String ORIGINAL_FILE = "src/test/resources/validation/dss1334/simple-test.xml";

	@Test
	public void test1a() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
	}

	@Test
	public void test1b() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");
		doc.setName(null);
		doc.setMimeType(null);
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
	}

	@Test
	public void test1c() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");
		doc.setName("");
		doc.setMimeType(null);
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
	}

	@Test
	public void test2() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/simple-test-signed-xades-baseline-b.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
	}

	@Test
	public void test3() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/simple-test.signed-only-detached-LuxTrustCA3.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new FileDocument(ORIGINAL_FILE)));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
	}

}
