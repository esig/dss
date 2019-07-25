package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESSignedDataExtendedAfterLTATest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		
		DSSDocument document = new FileDocument("src/test/resources/validation/cades_signeddata_extended_after_lta.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> allTimestamps = diagnosticData.getTimestampList();
		
		assertEquals(0, allTimestamps.get(0).getTimestampedRevocationIds().size());
		assertEquals(2, allTimestamps.get(1).getTimestampedRevocationIds().size());
		assertEquals(3, allTimestamps.get(2).getTimestampedRevocationIds().size());
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
