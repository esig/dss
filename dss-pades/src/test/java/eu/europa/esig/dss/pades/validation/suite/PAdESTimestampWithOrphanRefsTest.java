package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class PAdESTimestampWithOrphanRefsTest {
	
	@Test
	public void test() throws Exception {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-tst-with-orphan-refs.pdf"));

		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		List<TimestampToken> detachedTimestamps = validator.getDetachedTimestamps();
		for (TimestampToken timestampToken : detachedTimestamps) {
			
			PdfDocTimestampRevision pdfRevision = (PdfDocTimestampRevision) timestampToken.getPdfRevision();
			byte[] signedContent = PAdESUtils.getSignedContent(dssDocument, pdfRevision.getByteRange());
			
			SignedDocumentValidator timestampValidator = SignedDocumentValidator.fromDocument(new InMemoryDocument(timestampToken.getEncoded()));
			timestampValidator.setCertificateVerifier(new CommonCertificateVerifier());
			timestampValidator.setDetachedContents(Arrays.asList(new InMemoryDocument(signedContent)));
			
			Reports reports = timestampValidator.validateDocument();
			assertNotNull(reports);
			
			DiagnosticData diagnosticData = reports.getDiagnosticData();
			List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
			assertEquals(1, timestampList.size());
			
			TimestampWrapper timestampWrapper = timestampList.get(0);
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			
			SimpleReport simpleReport = reports.getSimpleReport();
			assertNotEquals(Indication.FAILED, simpleReport.getIndication(timestampToken.getDSSIdAsString()));
		}
		
		Reports reports = validator.validateDocument();
		// reports.print();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		
		int signatureTimestamps = 0;
		int archiveTimestamps = 0;
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++signatureTimestamps;
			} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++ archiveTimestamps;
			}
		}
		assertEquals(2, signatureTimestamps);
		assertEquals(2, archiveTimestamps);
		
		for (SignatureWrapper signatureWrapper : diagnosticData.getAllSignatures()) {
			SimpleReport simpleReport = reports.getSimpleReport();
			assertNotEquals(Indication.FAILED, simpleReport.getIndication(signatureWrapper.getId()));
			
			assertTrue(diagnosticData.getSignatureById(signatureWrapper.getId()).isBLevelTechnicallyValid());
		}
		
	}

}
