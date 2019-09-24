package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1636Test extends PKIFactoryAccess {

	@Test
	public void dss1636WithContentTimestampTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1636/detached_cts.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		TimestampWrapper timestampWrapper = timestampList.get(0);
		assertFalse(timestampWrapper.isMessageImprintDataFound());
		assertFalse(timestampWrapper.isMessageImprintDataIntact());
		assertTrue(timestampWrapper.isSignatureIntact());
		assertTrue(timestampWrapper.isSignatureValid());

		DetailedReport detailedReport = reports.getDetailedReport();
		List<String> timestampIds = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertEquals(1, timestampIds.size());
		String timestampId = timestampIds.iterator().next();
		Indication indication = detailedReport.getBasicBuildingBlocksIndication(timestampId);
		assertEquals(Indication.INDETERMINATE, indication);
		SubIndication subIndication = detailedReport.getBasicBuildingBlocksSubIndication(timestampId);
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, subIndication); // SHA1

		XmlBasicBuildingBlocks basicBuildingBlockById = detailedReport.getBasicBuildingBlockById(timestampId);
		assertNotNull(basicBuildingBlockById);
		XmlCV cv = basicBuildingBlockById.getCV();
		assertNotNull(cv);
		assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());
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
		assertEquals(Indication.INDETERMINATE, indication);
		SubIndication subIndication = detailedReport.getBasicBuildingBlocksSubIndication(timestampId);
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, subIndication); // SHA1

		XmlBasicBuildingBlocks basicBuildingBlockById = detailedReport.getBasicBuildingBlockById(timestampId);
		assertNotNull(basicBuildingBlockById);

		XmlCV cv = basicBuildingBlockById.getCV();
		assertNotNull(cv);
		assertEquals(Indication.FAILED, cv.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, cv.getConclusion().getSubIndication());
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
