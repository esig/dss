package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class DSS1419Test {

	@Test
	public void testSHA3_0() {
		// CAdES-BpB-att-SHA256-SHA3_256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA256-SHA3_256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_1() {
		// CAdES-BpB-att-SHA256-SHA3_256withRSAandMGF1.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA256-SHA3_256withRSAandMGF1.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_2() {
		// CAdES-BpB-att-SHA3_224-SHA256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_224-SHA256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_3() {
		// CAdES-BpB-att-SHA3_256-SHA256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_256-SHA256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_4() {
		// CAdES-BpB-att-SHA3_256-SHA3_256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_256-SHA3_256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_5() {
		// CAdES-BpB-att-SHA3_384-SHA256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_384-SHA256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_6() {
		// CAdES-BpB-att-SHA3_512-SHA256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_512-SHA256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
