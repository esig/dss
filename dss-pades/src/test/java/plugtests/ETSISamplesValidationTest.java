package plugtests;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.io.FileUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DetailedReport;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;

/**
 * This test is only to ensure that we don't have exception with valid? files
 */
@RunWith(Parameterized.class)
public class ETSISamplesValidationTest {

	@Parameters(name = "Validation {index} : {0}")
	public static Collection<Object[]> data() {
		File folder = new File("src/test/resources/plugtest");
		Collection<File> listFiles = FileUtils.listFiles(folder, new String[] { "pdf" }, true);
		Collection<Object[]> dataToRun = new ArrayList<Object[]>();
		for (File file : listFiles) {
			dataToRun.add(new Object[] { file });
		}
		return dataToRun;
	}

	private File fileToTest;

	public ETSISamplesValidationTest(File fileToTest) {
		this.fileToTest = fileToTest;
	}

	@Test
	public void testValidate() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(fileToTest));
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports validateDocument = validator.validateDocument();
		assertNotNull(validateDocument);

		DiagnosticData diagnosticData = validateDocument.getDiagnosticData();
		assertNotNull(diagnosticData);

		SimpleReport simpleReport = validateDocument.getSimpleReport();
		assertNotNull(simpleReport);

		DetailedReport detailedReport = validateDocument.getDetailedReport();
		assertNotNull(detailedReport);
	}

}
