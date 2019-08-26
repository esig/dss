package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

@RunWith(Parameterized.class)
public class DSS1690 {

	@Parameterized.Parameters
	public static Object[][] data() {
		return new Object[100][0];
	}

	public DSS1690() {
	}

	@Test
	public void validateArchiveTimestampsOrder() {

		String firstTimestampId = "T-32902C8337E0351C4AA33052A3E1DA9232D204C4839BB52879DF7183678CEE61";

		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/Test.signed_Certipost-2048-SHA512.extended-LTA.pdf"));

		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		TimestampWrapper firstATST = diagnosticData.getTimestampById(firstTimestampId);
		assertNotNull("Timestamp " + firstTimestampId + " not found", firstATST);
		List<String> timestampedTimestampsIds = firstATST.getTimestampedTimestampIds();
		assertEquals("First timestamp can't cover the second one", 0, timestampedTimestampsIds.size());
	}

	protected CertificateVerifier getOfflineCertificateVerifier() {
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setDataLoader(new IgnoreDataLoader());
		return cv;
	}
}
