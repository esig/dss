package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class DSS1972Test extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1959/pades-revoc-removed-from-dss-dict.pdf"));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
//		String orphanRevocationId = diagnosticData.getAllOrphanRevocationReferences().get(0).getId();
		
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (timestampWrapper.getType().isArchivalTimestamp()) {
//				List<OrphanTokenWrapper> allTimestampedOrphanTokens = timestampWrapper.getAllTimestampedOrphanTokens();
//				assertEquals(1, allTimestampedOrphanTokens.size());
//				assertEquals(orphanRevocationId, allTimestampedOrphanTokens.get(0).getId());
				
				++archiveTimestampCounter;
			}
		}
		assertEquals(3, archiveTimestampCounter);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
