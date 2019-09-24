package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1788Test {
	
	@Test
	public void testOriginal() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1788/dss1788-original.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		assertTrue(signature.isAttributePresent());
		assertTrue(signature.isDigestValuePresent());
		assertTrue(signature.isDigestValueMatch());
		assertTrue(signature.isIssuerSerialMatch());
		
		List<CertificateWrapper> certificateChain = signature.getCertificateChain();
		assertTrue(Utils.isCollectionNotEmpty(certificateChain));
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void testWithPublicKey() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1788/XAdESPublicKeyInKeyInfo.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		assertTrue(signature.isAttributePresent());
		assertTrue(signature.isDigestValuePresent());
		assertTrue(signature.isDigestValueMatch());
		assertTrue(signature.isIssuerSerialMatch());
		
		List<CertificateWrapper> certificateChain = signature.getCertificateChain();
		assertTrue(Utils.isCollectionNotEmpty(certificateChain));
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void testNoCertProvided() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1788/dss1788-noCertProvided.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNull(signingCertificate);
		byte[] signingCertificatePublicKey = signature.getSigningCertificatePublicKey();
		assertNotNull(signingCertificatePublicKey);
		assertTrue(signature.isAttributePresent());
		assertTrue(signature.isDigestValuePresent());
		assertFalse(signature.isDigestValueMatch());
		assertFalse(signature.isIssuerSerialMatch());
		
		List<CertificateWrapper> certificateChain = signature.getCertificateChain();
		assertFalse(Utils.isCollectionNotEmpty(certificateChain));
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void testCertProvidedIntoValidation() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1788/dss1788-noCertProvided.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.defineSigningCertificate(DSSUtils.loadCertificate(new File("src/test/resources/validation/dss1788/signCert.cer")));
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		assertTrue(signature.isAttributePresent());
		assertTrue(signature.isDigestValuePresent());
		assertTrue(signature.isDigestValueMatch());
		assertTrue(signature.isIssuerSerialMatch());
		
		List<CertificateWrapper> certificateChain = signature.getCertificateChain();
		assertTrue(Utils.isCollectionNotEmpty(certificateChain));
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

}
