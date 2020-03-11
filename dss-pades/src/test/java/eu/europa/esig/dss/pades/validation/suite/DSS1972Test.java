package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanTokenWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1972Test {
	
	@Test
	public void test() throws Exception {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1959/pades-revoc-removed-from-dss-dict.pdf"));

		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		// reports.print();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		
		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
		assertEquals(1, diagnosticData.getAllOrphanRevocationReferences().size());
		
		String orphanRevocationId = diagnosticData.getAllOrphanRevocationReferences().get(0).getId();
		
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (timestampWrapper.getType().isArchivalTimestamp()) {
				List<OrphanTokenWrapper> allTimestampedOrphanTokens = timestampWrapper.getAllTimestampedOrphanTokens();
				assertEquals(1, allTimestampedOrphanTokens.size());
				assertEquals(orphanRevocationId, allTimestampedOrphanTokens.get(0).getId());
				
				++archiveTimestampCounter;
			}
		}
		assertEquals(3, archiveTimestampCounter);
		
	}

}
