/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.validation.esig.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.esig.test.ESigValidationCasesRepository.ValidationTest;
import eu.europa.esig.dss.xades.validation.esig.test.ESigValidationCasesRepository.LOTLConfig;
import eu.europa.esig.trustedlist.TrustedListUtils;

/**
 * This class tests all validation cases provided by the Validation esig test
 * cases project. See https://webgate.ec.europa.eu/esig-validation-tests/home
 * <p>
 * Note : as test cases largely depend on current date, test cases data is
 * recreated every week. Therefore we start by downloading the latest test
 * files.
 * <p>
 * By default, all validation cases are run. In order to run a specific set or a
 * single validation case, a <code>eSigTestPrefixFilter</code> parameter may be
 * passed on command line to filter tests based on their numeric prefix.
 * Examples :
 * <ul>
 * <li><code>"mvn clean install -DargLine="-DeSigTestPrefixFilter=3.2.1-"</code>
 * would run only test 3.2.1</li>
 * <li><code>"mvn clean install -DargLine="-DeSigTestPrefixFilter=2."</code>
 * would run all 2.*.* tests</li>
 * </ul>
 * 
 * @author Nicolas ROY
 */
public class EsigValidationCasesTest {

	private static final Logger logger = LoggerFactory.getLogger(EsigValidationCasesTest.class);

	/**
	 * The configured LOTL configuration... Will change when testing, depending on
	 * LOTL config required by test
	 * 
	 * Note : must be static, as parametrized tests instanciates this class for each
	 * test
	 */
	private static LOTLConfig currentConfig;

	private static TrustedListsCertificateSource trustedListsCertificateSource;

	/**
	 * If not null, will run tests starting with the given prefix
	 */
	private static final String RUN_ONLY_TEST_WITH_PREFIX = System.getProperty("eSigTestPrefixFilter");

	/**
	 * Obtain the collection of validationTests to run
	 */
	public static Iterable<? extends Object> getEsigValidationTestCases()
			throws IOException, ParserConfigurationException, SAXException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException {
		logger.info("Downloading and parsing Validation esig test cases...");
		ESigValidationCasesRepository validationTestsRepository = new ESigValidationCasesRepository();

		if (RUN_ONLY_TEST_WITH_PREFIX == null) {
			logger.info("Runnning all Validation esig test cases as eSigTestPrefixFilter is null");
			return validationTestsRepository.getValidationTests();

		} else {
			logger.info("Runnning only tests with prefix \"" + RUN_ONLY_TEST_WITH_PREFIX
					+ "\" as eSigTestPrefixFilter property is set to this value.");
			List<ValidationTest> result = new ArrayList<ESigValidationCasesRepository.ValidationTest>();
			for (ValidationTest validationTest : validationTestsRepository.getValidationTests()) {
				if (validationTest.getTestFile().getName().startsWith(RUN_ONLY_TEST_WITH_PREFIX)) {
					result.add(validationTest);
				}
			}
			return result;
		}
	}

	/**
	 * Init the LOTL for provided test. Will be done only if LOTL configuration
	 * (i.e. URL) is different from previous call of this method.
	 * 
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public void initLotlIfNeeded(ValidationTest validationTest) throws IOException, InterruptedException {
		// If current LOTL config is is not equal to the LOTL config we'll have to
		// launch, then change it !
		LOTLConfig nextConfig = validationTest.getLotlConfig();
		if (!nextConfig.equals(currentConfig)) {

			logger.info("Initializing TLManager with " + nextConfig);

			// Disable validation of TrustLists, see : comment in TrustedListUtils shadow
			// version for a full explanation.
			TrustedListUtils.getInstance().setValidate(false);
			try {
				trustedListsCertificateSource = initLotl(nextConfig.getLotlUrl(), nextConfig.getLotlP12(),
						nextConfig.getLotlP12Password());

			} finally {
				TrustedListUtils.getInstance().setValidate(true);
			}
			currentConfig = nextConfig;
		}
	}

	/**
	 * test the signature validation for a single ValidationTest
	 * 
	 * @throws InterruptedException
	 */
	@ParameterizedTest
	@MethodSource("getEsigValidationTestCases")
	public void testValidate(ValidationTest validationTest)
			throws JAXBException, XMLStreamException, IOException, SAXException, InterruptedException {

		this.initLotlIfNeeded(validationTest);

		try {
			ValidationPolicyFacade policyFacade = ValidationPolicyFacade.newFacade();
			ConstraintsParameters constraints = policyFacade.unmarshall(new File("src/test/resources/constraint.xml"));

			DSSDocument documentToValidate = new InMemoryDocument(new FileInputStream(validationTest.getTestFile()));
			SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(documentToValidate);

			CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
			certificateVerifier.setDataLoader(new CommonsDataLoader());
			certificateVerifier.setDataLoader(getFileCacheDataLoader());
			certificateVerifier.setCrlSource(new OnlineCRLSource(getFileCacheDataLoader()));
			OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
			onlineOCSPSource.setDataLoader(getFileCacheDataLoader());
			certificateVerifier.setOcspSource(onlineOCSPSource);

			certificateVerifier.setTrustedCertSources(trustedListsCertificateSource);

			documentValidator.setCertificateVerifier(certificateVerifier);
			documentValidator.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);

			Reports reports = documentValidator.validateDocument(constraints);
			SimpleReport simpleReport = reports.getSimpleReport();

			String firstSignatureId = simpleReport.getFirstSignatureId();

			String actualResult = simpleReport.getSignatureQualification(firstSignatureId).getReadable();

			assertEquals(validationTest.getExpectedConclusion(), actualResult,
					"For " + validationTest.toString() + ", got unexpected level: " + actualResult + " (Expected: "
							+ validationTest.getExpectedConclusion() + "). Subindication: "
							+ simpleReport.getSubIndication(firstSignatureId) + ". ");

		} catch (Exception e) {
			logger.error("Exception for test " + validationTest + " : " + e);
			throw e;
		}
	}

	/**
	 * Init with provided LOTL url, keystore and keystore password.
	 * 
	 * @throws IOException
	 */
	private static TrustedListsCertificateSource initLotl(String lotlUrl, File keystoreFile, String keystorePassword)
			throws IOException {

		TLValidationJob job = new TLValidationJob();
		job.setOnlineDataLoader(new FileCacheDataLoader(new CommonsDataLoader()));

		TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
		job.setTrustedListCertificateSource(trustedListsCertificateSource);

		KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(keystoreFile, "PKCS12",
				keystorePassword);

		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setUrl(lotlUrl);
		lotlSource.setCertificateSource(keyStoreCertificateSource);
		lotlSource.setPivotSupport(true);

		job.setListOfTrustedListSources(lotlSource);

		// application initialization
		job.onlineRefresh();

		// check LOTL signature status
		TLValidationJobSummary lotlValidation = job.getSummary();
		for (LOTLInfo euLotlInfo : lotlValidation.getLOTLInfos()) {
			assertFalse(euLotlInfo.getValidationCacheInfo().isError());
			assertTrue(euLotlInfo.getValidationCacheInfo().isValid());
		}

		return trustedListsCertificateSource;
	}

	/**
	 * Get file cache data loader to store docs that intervene in the validation
	 * process
	 * 
	 * @return
	 */
	private DataLoader getFileCacheDataLoader() {
		FileCacheDataLoader cacheDataLoader = new FileCacheDataLoader();

		CommonsDataLoader dataLoader = new CommonsDataLoader();
		cacheDataLoader.setDataLoader(dataLoader);

		File rootFolder = new File(System.getProperty("java.io.tmpdir"));
		File tslCache = new File(rootFolder, "dss-cache");
		cacheDataLoader.setFileCacheDirectory(tslCache);
		return cacheDataLoader;
	}
}
