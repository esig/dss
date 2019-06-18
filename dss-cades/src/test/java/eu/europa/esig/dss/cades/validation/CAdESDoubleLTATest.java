package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.TimestampType;

public class CAdESDoubleLTATest extends PKIFactoryAccess {
	
	@Test
	public void test() {

		DSSDocument document = new FileDocument("src/test/resources/validation/CAdESDoubleLTA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		Set<TimestampWrapper> allTimestamps = diagnosticData.getTimestampSet();
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
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	

}
