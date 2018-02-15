package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class CustomProcessExecutorTest {

	private static final Logger LOG = LoggerFactory.getLogger(CustomProcessExecutorTest.class);

	@Test
	public void skipRevocationDataValidation() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/it.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyNoRevoc());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void signedDataNotFound() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/signed_data_not_found.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void noPoeRevokedNoTimestamp() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/no_poe_revoked_no_timestamp.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_POE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void passedRevokedWithTimestamp() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/passed_revoked_with_timestamp.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(1, timestampIds.size());

		assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(timestampIds.get(0)));

		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void passedOutOfBoundsWithTimestamps() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/passed_out_of_bounds_with_timestamps.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(5, timestampIds.size());
		for (String tspId : timestampIds) {
			assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(tspId));
		}

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void timestampsSameSecond() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/timestamps_same_second.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		List<String> warnings = simpleReport.getWarnings(simpleReport.getFirstSignatureId());
		assertFalse(warnings.contains(MessageTag.TSV_ASTPTCT_ANS.getMessage()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(5, timestampIds.size());
		for (String tspId : timestampIds) {
			assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(tspId));
		}

		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void timestampsIncorrectOrder() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/timestamps_same_second_incorrect_order.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		List<String> warnings = simpleReport.getWarnings(simpleReport.getFirstSignatureId());
		assertTrue(warnings.contains(MessageTag.TSV_ASTPTCT_ANS.getMessage()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(5, timestampIds.size());
		for (String tspId : timestampIds) {
			assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(tspId));
		}

		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void hashFailure() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/hash_failure.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.FAILED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.FAILED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.FAILED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void sigConstraintFailure() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/sig_constraint_failure.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.FAILED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.FAILED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.FAILED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void signingCertificateNotFound() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/signing_certificate_not_found.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		Date currentTime = sdf.parse("04/05/2016 15:55:00");
		executor.setCurrentTime(currentTime);

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void testDSS943() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/DSS-943/NotQualified-service.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyNoRevoc());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void testDSS956AllValidationLevels() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/passed_revoked_with_timestamp.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
		checkReports(executor.execute());

		executor.setValidationLevel(ValidationLevel.TIMESTAMPS);
		checkReports(executor.execute());

		executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
		checkReports(executor.execute());

		executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
		checkReports(executor.execute());
	}

	@Test
	public void qualification() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/preEIDAS.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.INDETERMINATE_ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qualificationQESig() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/qualifQESig.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void rsa1023() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/rsa1023.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicBuildingBlocksSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_POE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qualificationNA() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/qualifNA.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.NA, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void noSigningTime() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/no-signing-date.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void testCertChain() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/qualifNA.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(1, simpleReport.getJaxbModel().getSignaturesCount());
		XmlSignature xmlSignature = simpleReport.getJaxbModel().getSignature().get(0);
		assertTrue(!xmlSignature.getCertificateChain().getCertificate().isEmpty());
		assertEquals(3, xmlSignature.getCertificateChain().getCertificate().size());
		ByteArrayOutputStream s = new ByteArrayOutputStream();
		JAXB.marshal(simpleReport.getJaxbModel(), s);
	}

	@Test
	public void testWithoutCertChain() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/qualifNAWithoutCertChain.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(1, simpleReport.getJaxbModel().getSignaturesCount());
		XmlSignature xmlSignature = simpleReport.getJaxbModel().getSignature().get(0);
		assertEquals(null, xmlSignature.getCertificateChain());
	}

	@Test
	public void testMultiSigs() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/multi-sign.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(4, simpleReport.getJaxbModel().getSignaturesCount());

		LOG.info(reports.getXmlSimpleReport());

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(4, detailedReport.getSignatureIds().size());

		LOG.info(reports.getXmlDetailedReport());
	}

	@Test
	public void testCounterSignature() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/counter-signature-diag-data.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(2, simpleReport.getJaxbModel().getSignaturesCount());

		LOG.info(reports.getXmlSimpleReport());

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(2, detailedReport.getSignatureIds().size());

		LOG.info(reports.getXmlDetailedReport());
	}

	@Test
	public void multiFiles() throws Exception {

		FileInputStream fis = new FileInputStream("src/test/resources/asic-e-multi-files-diag-data.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void multiFilesNoManifest() throws Exception {

		FileInputStream fis = new FileInputStream("src/test/resources/asic-e-multi-files-no-manifest-diag-data.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void asicEXades() throws Exception {

		FileInputStream fis = new FileInputStream("src/test/resources/asic-e-xades-diag-data.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void asicSXades() throws Exception {

		FileInputStream fis = new FileInputStream("src/test/resources/asic-s-xades-diag-data.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void testDSS1330() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/DSS-1330-diag-data.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	private void checkReports(Reports reports) {
		// reports.print();
		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticData());
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getSimpleReport());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getDetailedReport());
		assertNotNull(reports.getDetailedReportJaxb());
		assertTrue(Utils.isStringNotBlank(reports.getXmlDiagnosticData()));
		assertTrue(Utils.isStringNotBlank(reports.getXmlSimpleReport()));
		assertTrue(Utils.isStringNotBlank(reports.getXmlDetailedReport()));
	}

	private EtsiValidationPolicy loadPolicy() throws Exception {
		FileInputStream policyFis = new FileInputStream("src/main/resources/policy/constraint.xml");
		ConstraintsParameters policyJaxB = getJAXBObjectFromString(policyFis, ConstraintsParameters.class, "/xsd/policy.xsd");
		assertNotNull(policyJaxB);
		return new EtsiValidationPolicy(policyJaxB);
	}

	private EtsiValidationPolicy loadPolicyNoRevoc() throws Exception {
		FileInputStream policyFis = new FileInputStream("src/test/resources/constraint-no-revoc.xml");
		ConstraintsParameters policyJaxB = getJAXBObjectFromString(policyFis, ConstraintsParameters.class, "/xsd/policy.xsd");
		assertNotNull(policyJaxB);
		return new EtsiValidationPolicy(policyJaxB);
	}

	@SuppressWarnings("unchecked")
	private <T extends Object> T getJAXBObjectFromString(InputStream is, Class<T> clazz, String xsd) throws Exception {
		JAXBContext context = JAXBContext.newInstance(clazz.getPackage().getName());
		Unmarshaller unmarshaller = context.createUnmarshaller();
		if (Utils.isStringNotEmpty(xsd)) {
			SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			InputStream inputStream = this.getClass().getResourceAsStream(xsd);
			Source source = new StreamSource(inputStream);
			Schema schema = sf.newSchema(source);
			unmarshaller.setSchema(schema);
		}
		return (T) unmarshaller.unmarshal(is);
	}

}
