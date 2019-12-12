package eu.europa.esig.dss.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.SingleTimestampValidator;

public class TimestampValidatorTest {
	
	@Test
	public void testWithAttached() throws Exception {
		DSSDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");
		DSSDocument timestampedContent = new InMemoryDocument("Test123".getBytes());
		SingleTimestampValidator timestampValidator = new SingleTimestampValidator(timestamp, timestampedContent, TimestampType.CONTENT_TIMESTAMP,
				new CertificatePool());
		timestampValidator.setCertificateVerifier(new CommonCertificateVerifier());
		
		validate(timestampValidator);
	}
	
	@Test
	public void testWithDigestDocument() throws Exception {
		DSSDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");
		DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA256, 
				Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, "Test123".getBytes())));
		SingleTimestampValidator timestampValidator = new SingleTimestampValidator(timestamp, digestDocument, TimestampType.CONTENT_TIMESTAMP,
				new CertificatePool());
		timestampValidator.setCertificateVerifier(new CommonCertificateVerifier());
		
		validate(timestampValidator);
	}
	
	private void validate(SingleTimestampValidator timestampValidator) throws Exception {
		
		Reports reports = timestampValidator.validateDocument();
		
		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getXmlDiagnosticData());
		assertNotNull(reports.getDetailedReportJaxb());
		assertNotNull(reports.getXmlDetailedReport());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getXmlSimpleReport());

		SimpleReportFacade simpleReportFacade = SimpleReportFacade.newFacade();
		String marshalled = simpleReportFacade.marshall(reports.getSimpleReportJaxb(), true);
		assertNotNull(marshalled);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		TimestampWrapper timestampWrapper = timestampList.get(0);
		
		assertTrue(timestampWrapper.isMessageImprintDataFound());
		assertTrue(timestampWrapper.isMessageImprintDataIntact());
	}

}
