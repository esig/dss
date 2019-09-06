package eu.europa.esig.dss.pades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import org.junit.jupiter.api.RepeatedTest;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1690 {

	@RepeatedTest(100)
	public void validateArchiveTimestampsOrder() {

		String firstTimestampId = "T-32902C8337E0351C4AA33052A3E1DA9232D204C4839BB52879DF7183678CEE61";

		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/Test.signed_Certipost-2048-SHA512.extended-LTA.pdf"));

		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		TimestampWrapper firstATST = diagnosticData.getTimestampById(firstTimestampId);
		assertNotNull(firstATST, "Timestamp " + firstTimestampId + " not found");
		List<String> timestampedTimestampsIds = firstATST.getTimestampedTimestampIds();
		assertEquals(0, timestampedTimestampsIds.size(), "First timestamp can't cover the second one");
	}

	protected CertificateVerifier getOfflineCertificateVerifier() {
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setDataLoader(new IgnoreDataLoader());
		return cv;
	}
}
