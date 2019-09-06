package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESDoubleLTATest extends PKIFactoryAccess {
	
	@Test
	public void test() {

		DSSDocument document = new FileDocument("src/test/resources/validation/CAdESDoubleLTA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> allTimestamps = diagnosticData.getTimestampList();
		assertNotNull(allTimestamps);
		assertEquals(3, allTimestamps.size());
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestampWrapper : allTimestamps) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				archiveTimestampCounter++;
				assertEquals(ArchiveTimestampType.CAdES_V3, timestampWrapper.getArchiveTimestampType());
			}
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
		}
		assertEquals(2, archiveTimestampCounter);
		
		assertEquals(0, allTimestamps.get(0).getTimestampedRevocationIds().size());
		assertEquals(2, allTimestamps.get(1).getTimestampedRevocationIds().size());
		assertEquals(2, allTimestamps.get(2).getTimestampedRevocationIds().size());
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	

}
