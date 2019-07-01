package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

public class DSS1688Test {
	
	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1688/dss1688.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		DSSDocument detachedDocument = new FileDocument("src/test/resources/validation/dss1688/dss1688-detached-content.xml");
		validator.setDetachedContents(Arrays.asList(detachedDocument));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> allTimestamps = diagnosticData.getTimestampList();
		for (TimestampWrapper timestamp : allTimestamps) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
		
	}

}
