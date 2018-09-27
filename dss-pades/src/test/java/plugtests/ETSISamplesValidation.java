package plugtests;

import static org.junit.Assert.assertNotNull;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

/**
 * This test is only to ensure that we don't have exception with valid? files
 */
@RunWith(Parameterized.class)
public class ETSISamplesValidation {


	@Parameters(name = "Validation {index} : {0}")
	public static Collection<Object[]> data() throws IOException {

		// We use this file because File.listFiles() doesn't work from another jar
		String listFiles = "/plugtest/plugtest_files.txt";

		Collection<Object[]> dataToRun = new ArrayList<Object[]>();
		try (BufferedReader br = new BufferedReader(new InputStreamReader(ETSISamplesValidation.class.getResourceAsStream(listFiles)))) {
			String filepath;
			while ((filepath = br.readLine()) != null) {
				dataToRun.add(new Object[] { new InMemoryDocument(ETSISamplesValidation.class.getResourceAsStream(filepath)) });
			}

		}
		return dataToRun;
	}

	private DSSDocument doc;

	public ETSISamplesValidation(DSSDocument doc) {
		this.doc = doc;
	}

	@Test
	public void testValidate() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports validateDocument = validator.validateDocument();
		assertNotNull(validateDocument);

		DiagnosticData diagnosticData = validateDocument.getDiagnosticData();
		assertNotNull(diagnosticData);

		SimpleReport simpleReport = validateDocument.getSimpleReport();
		assertNotNull(simpleReport);

		DetailedReport detailedReport = validateDocument.getDetailedReport();
		assertNotNull(detailedReport);

		// validateDocument.print();
	}

}
