package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

/**
 * Test for XML Signature wrapping detection
 */
public class XMLSignatureWrappingTest {

	@Test
	public void testEnvelopedFakeSignedProperties() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloped-fake-signedProperties.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void testEnvelopedOriginal() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/original.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());
	}

	@Test
	public void testEnvelopedFakeContent() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloped-fake-content.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());

		List<XmlSignatureScope> signatureScopes = signatureById.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		assertEquals(XmlElementSignatureScope.class.getSimpleName(), signatureScopes.get(0).getScope());
	}

	@Test
	public void testCY() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/TSL-CY-sign.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());

		List<XmlSignatureScope> signatureScopes = signatureById.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		assertEquals(XmlRootSignatureScope.class.getSimpleName(), signatureScopes.get(0).getScope());
	}

	@Test
	public void testNoId() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/TSL-noID.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());

		List<XmlSignatureScope> signatureScopes = signatureById.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		assertEquals(XmlRootSignatureScope.class.getSimpleName(), signatureScopes.get(0).getScope());
	}

	@Test
	public void testEnvelopedFakeContentMisplaced() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloped-fake-content-misplaced.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());

		List<XmlSignatureScope> signatureScopes = signatureById.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		assertEquals(XmlElementSignatureScope.class.getSimpleName(), signatureScopes.get(0).getScope());
	}

	@Test
	public void testEnvelopedFakeContentTwoSameIds() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloped-fake-content-two-same-id.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void testEnvelopingFakeObject() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloping-fake-object.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void testEnvelopingFakeManifest() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloping-fake-manifest.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

}
