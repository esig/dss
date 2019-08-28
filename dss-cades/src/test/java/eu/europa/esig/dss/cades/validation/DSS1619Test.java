package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1619Test extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1619/CAdES-XL-T1-Double-AV2.png.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();

		// System.out.println(reports.getXmlDiagnosticData().replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", ""));
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(8, timestampList.size());
		
		int archiveTimestampCounter = 0;
		int timestampsWithArchiveTypeCounter = 0;
		int timestampV2Counter = 0;
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				archiveTimestampCounter++;
				assertNotNull(timestamp.getArchiveTimestampType());
			}
			if (timestamp.getArchiveTimestampType() != null) {
				timestampsWithArchiveTypeCounter++;
				if (ArchiveTimestampType.CAdES_V2.equals(timestamp.getArchiveTimestampType())) {
					timestampV2Counter++;
				}
			}
		}
		assertEquals(2, archiveTimestampCounter);
		assertEquals(2, timestampsWithArchiveTypeCounter);
		assertEquals(2, timestampV2Counter);
		
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
