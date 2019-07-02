package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedTimestamp;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

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
		List<XmlTimestampedObject> timestampedObjects = firstATST.getTimestampedObjects();
		for (XmlTimestampedObject xmlTimestampedObject : timestampedObjects) {
			if (xmlTimestampedObject instanceof XmlTimestampedTimestamp) {
				fail("First timestamp can't cover the second one");
			}
		}

	}

	protected CertificateVerifier getOfflineCertificateVerifier() {
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setDataLoader(new IgnoreDataLoader());
		return cv;
	}
}
