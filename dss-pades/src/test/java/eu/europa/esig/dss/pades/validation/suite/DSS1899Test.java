package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

/* Test timestamp type correctness */
public class DSS1899Test {
	
	@Test
	public void timestampWithSigTypeTest() {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-tst-with-sig-type.pdf"));

		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getSignatures().size());
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SignatureLevel.PAdES_BASELINE_LT, signature.getSignatureFormat());
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestampList.get(0).getType());
		
	}
	
	@Test
	public void timestampWithNullTypeTest() {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-tst-with-null-type.pdf"));

		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getSignatures().size());
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SignatureLevel.PAdES_BASELINE_LTA, signature.getSignatureFormat());
		
		assertNotNull(signature.getFirstFieldName());
		assertTrue(Utils.isCollectionNotEmpty(signature.getSignatureFieldNames()));
		assertEquals(1, signature.getSignatureFieldNames().size());
		assertNotNull(signature.getSignatureDictionaryType());
		assertNotNull(signature.getFilter());
		assertNotNull(signature.getSubFilter());
		assertNotNull(signature.getSignatureByteRange());
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		TimestampWrapper archiveTimestamp = null;
		for (TimestampWrapper timestamp : timestampList) {
			if (timestamp.getType().isArchivalTimestamp()) {
				archiveTimestamp = timestamp;
			}
		}
		
		assertNotNull(archiveTimestamp);
		assertNull(archiveTimestamp.getSignatureDictionaryType());
		assertTrue(Utils.isCollectionNotEmpty(archiveTimestamp.getSignatureFieldNames()));
		assertTrue(Utils.isCollectionNotEmpty(archiveTimestamp.getSignatureByteRange()));
		assertNotNull(archiveTimestamp.getFilter());
		assertNotNull(archiveTimestamp.getSubFilter());
		
	}

}
