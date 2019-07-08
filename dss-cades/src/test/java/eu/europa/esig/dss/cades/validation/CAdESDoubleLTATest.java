package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

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
		int counter = 0;
		for (TimestampWrapper timestampWrapper : allTimestamps) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				counter++;
			}
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
		}
		assertEquals(2, counter);
		
		assertEquals(0, allTimestamps.get(0).getTimestampedRevocationIds().size());
		assertEquals(2, allTimestamps.get(1).getTimestampedRevocationIds().size());
		assertEquals(2, allTimestamps.get(2).getTimestampedRevocationIds().size());
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	

}
