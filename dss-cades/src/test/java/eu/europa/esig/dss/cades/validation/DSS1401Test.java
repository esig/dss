package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.TimestampType;

public class DSS1401Test {

	@Test
	public void testFile1() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1401/sig_with_atsv2.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		TimestampWrapper archiveTimestamp = timestamps.get(0);

		assertTrue(archiveTimestamp.isMessageImprintDataIntact());

	}

	@Test
	public void testFile2() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-916/test.txt.signed_Certipost-2048.detached.old.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.setDetachedContents(Arrays.<DSSDocument> asList(new FileDocument("src/test/resources/validation/dss-916/test.txt")));
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		TimestampWrapper archiveTimestamp = timestamps.get(0);

		assertTrue(archiveTimestamp.isMessageImprintDataIntact());

	}

	@Test
	public void testFile3() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-916/test.txt.signed.qes.attached.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		TimestampWrapper archiveTimestamp = timestamps.get(0);

		assertTrue(archiveTimestamp.isMessageImprintDataIntact());

	}

	@Test
	public void testFile4() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-916/test.txt.signed.qes.detached.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.setDetachedContents(Arrays.<DSSDocument> asList(new FileDocument("src/test/resources/validation/dss-916/test.txt")));
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		TimestampWrapper archiveTimestamp = timestamps.get(0);

		assertTrue(archiveTimestamp.isMessageImprintDataIntact());

	}

	@Test
	public void testFile5() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1344/screenshot.png.signed_qes_detached.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.setDetachedContents(Arrays.<DSSDocument> asList(new FileDocument("src/test/resources/validation/dss-1344/screenshot.png")));
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		TimestampWrapper archiveTimestamp = timestamps.get(0);

		assertTrue(archiveTimestamp.isMessageImprintDataIntact());

	}

}
