package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
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
		
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
		
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
