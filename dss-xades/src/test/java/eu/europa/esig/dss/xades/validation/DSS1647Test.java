package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

public class DSS1647Test {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss-1647_OJ_L_2018_109_FULL.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		//commonCertificateVerifier.setIncludeCertificateRevocationValues(true);
		validator.setCertificateVerifier(commonCertificateVerifier);
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertNotNull(timestamps);

	}

}
