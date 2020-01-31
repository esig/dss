package eu.europa.esig.dss.integration;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.test.signature.UnmarshallingTester;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * This test is only to ensure that we don't have exception with valid? files
 */
public class SignaturePoolTest {

	private static Stream<Arguments> data() throws IOException {

		// -Dsignature.pool.folder=...

		String signaturePoolFolder = System.getProperty("signature.pool.folder", "src/main/soapui");
		File folder = new File(signaturePoolFolder);
		Collection<File> listFiles = Utils.listFiles(folder,
				new String[] { "asice", "asics", "bdoc", "csig", "ddoc", "es3", "p7", "p7b", "p7m", "p7s", "pdf", "pkcs7", "xml", "xsig" }, true);
		Collection<Arguments> dataToRun = new ArrayList<>();
		for (File file : listFiles) {
			dataToRun.add(Arguments.of(file));
		}
		return dataToRun.stream();
	}

	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	public void testValidate(File fileToTest) {

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(fileToTest));

		// Offline validation
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticData());
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getSimpleReport());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getDetailedReport());
		assertNotNull(reports.getDetailedReportJaxb());

		UnmarshallingTester.unmarshallXmlReports(reports);
	}

}