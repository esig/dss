package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class DSS1636Test extends PKIFactoryAccess {
	
	@Test
	public void dss1636WithContentTimestampTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1636/detached_cts.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		DetailedReport detailedReport = reports.getDetailedReport();
		List<String> timestampIds = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertEquals(1, timestampIds.size());
		String timestampId = timestampIds.iterator().next();
		Indication indication = detailedReport.getBasicBuildingBlocksIndication(timestampId);
		assertEquals(Indication.INDETERMINATE, indication);
		SubIndication subIndication = detailedReport.getBasicBuildingBlocksSubIndication(timestampId);
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, subIndication);
	}
	
	@Test
	public void dss1636WithContentTimestampAndIncorrectDataTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1636/detached_cts.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new InMemoryDocument(new byte[] { 1, 2, 3 })));
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		DetailedReport detailedReport = reports.getDetailedReport();
		List<String> timestampIds = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertEquals(1, timestampIds.size());
		String timestampId = timestampIds.iterator().next();
		Indication indication = detailedReport.getBasicBuildingBlocksIndication(timestampId);
		assertEquals(Indication.FAILED, indication);
		SubIndication subIndication = detailedReport.getBasicBuildingBlocksSubIndication(timestampId);
		assertEquals(SubIndication.HASH_FAILURE, subIndication);
	}

	@Test
	public void dss1636WithoutContentTimestampTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1636/detached_no_cts.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
