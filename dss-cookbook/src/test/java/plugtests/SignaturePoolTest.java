package plugtests;

import static java.time.Duration.ofSeconds;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeout;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.test.UnmarshallingTester;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.ValidationReportUtils;

/**
 * This test is only to ensure that we don't have exception with valid? files
 */
public class SignaturePoolTest {
	
	private static final Logger LOG = LoggerFactory.getLogger(SignaturePoolTest.class);
	
	@BeforeAll
	public static void init() throws Exception {
		// preload JAXB context before validation
		ValidationReportUtils.getInstance().getJAXBContext();
	}

	private static Stream<Arguments> data() throws IOException {

		// -Dsignature.pool.folder=...

		String signaturePoolFolder = System.getProperty("signature.pool.folder", "src/test/resources/signature-pool");
		File folder = new File(signaturePoolFolder);
		Collection<File> listFiles = Utils.listFiles(folder, new String[] { "asice", "asics", "bdoc", "csig", "ddoc",
				"es3", "p7", "p7b", "p7m", "p7s", "pdf", "pkcs7", "xml", "xsig" }, true);
		Collection<Arguments> dataToRun = new ArrayList<>();
		for (File file : listFiles) {
			dataToRun.add(Arguments.of(file));
		}
		return dataToRun.stream();
	}

	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	public void testValidate(File fileToTest) {
		LOG.info("Begin : {}", fileToTest.getAbsolutePath());
		assertTimeout(ofSeconds(3L), () -> execute(fileToTest));
		LOG.info("End : {}", fileToTest.getAbsolutePath());
	}

	private void execute(File fileToTest) {
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