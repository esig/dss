package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
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
		assertNotNull(reports);
		// reports.print();
		
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
		assertNotNull(reports);
		// reports.print();
		
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
		assertNotNull(reports);
		// reports.print();
		
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
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void testCertProvidedIntoValidation() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1788/dss1788-noCertProvided.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.defineSigningCertificate(DSSUtils.loadCertificate(new File("src/test/resources/validation/dss1788/signCert.cer")));
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		// reports.print();
		
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
		
		// cert found, but chain is not trusted
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void certPresentInCertValuesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1788/dss1920-cert-in-certValues.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		// reports.print();
		
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
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void certPresentInCertValuesWithoutPublicKeyTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1788/dss1920-cert-in-certValues-without-publicKey.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		// reports.print();
		
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
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void certFromTrustedStoreTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1788/dss1788-noCertProvided.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		
		CertificateToken signingCertificateToken = DSSUtils.loadCertificate(new File("src/test/resources/validation/dss1788/signCert.cer"));
		
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		trustedCertSource.addCertificate(signingCertificateToken);
		commonCertificateVerifier.setTrustedCertSource(trustedCertSource);
		validator.setCertificateVerifier(commonCertificateVerifier);
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		// reports.print();
		
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
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

}
