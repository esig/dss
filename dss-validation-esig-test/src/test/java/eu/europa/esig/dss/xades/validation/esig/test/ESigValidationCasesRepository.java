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

import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is responsible for downloading Validation eSig tests, and allows
 * iterating over tests. Tests with same LOTL config are contiguous in list.
 * 
 * See : https://webgate.ec.europa.eu/esig-validation-tests
 * 
 * @author Nicolas ROY 
 */
public class ESigValidationCasesRepository {

	private static final Logger logger = LoggerFactory.getLogger(ESigValidationCasesRepository.class);

	/**
	 * Actually, LOTL and associated P12 update may be quite chaotic on Test
	 * Validation website. For example, provided P12 for LOTL-2 and LOTL-3 were
	 * updated on 2020-09-24, but LOTLs were not updated (and were still signed with
	 * previous certificate issued on 2020-09-19, even after 24h).
	 * 
	 * Therefore, we have a mechanism to take the certificate from the LOTL and make
	 * it the P12.
	 * 
	 * Disabled as the update bug does not seem to reappear (2020-11-16).
	 */
	private static final boolean FIX_LOTL_P12 = false;

	/**
	 * Points to a ZIP, containing a ZIP for each LOTL
	 */
	private static final String CASES_DOWNLOAD_URL = "https://webgate.ec.europa.eu/esig-validation-tests/testcase/testFile/all";
	private static final FileFilter LOTL_URL_FILTER = new FileSuffixFilter("LOTL URL.txt");
	private static final FileFilter LOTL_P12_FILTER = new FileSuffixFilter(".p12");
	private static final FileFilter LOTL_P12_PASSWORD_FILTER = new FileSuffixFilter("PASSWORD.txt");

	private static final String TEST_FILE_SUFFIX = "-TEST FILE.xml";
	private static final String CONCLUSION_FILE_SUFFIX = "-CONCLUSION.txt";
	private static final FileFilter TEST_FILE_FILTER = new FileSuffixFilter(TEST_FILE_SUFFIX);

	// Folder where cases are downloaded
	private final String casesFolder = "./target/ValidationCases" + System.currentTimeMillis();

	/**
	 * The actual list of all Validation tests. Note : tests with same LOTL config
	 * are contiguous in this list
	 */
	private final List<ValidationTest> validationTests = new ArrayList<>();

	/**
	 * Create the repository by downloading, unzipping and parsing files.
	 * 
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	public ESigValidationCasesRepository() throws IOException, ParserConfigurationException, SAXException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException {
		new File(casesFolder).mkdir();

		URL url = new URL(CASES_DOWNLOAD_URL);
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();

		// Unexpected response ?
		if (HttpURLConnection.HTTP_OK != connection.getResponseCode()) {
			fail("Unexpected response while downloading test cases from URL " + CASES_DOWNLOAD_URL + " Response code : "
					+ connection.getResponseCode() + ". Body : " + getString(connection.getInputStream()));
		}

		ZipInputStream zis = new ZipInputStream(connection.getInputStream());

		// Unzip the content in CASES_FOLDER
		ZipEntry entry;
		while ((entry = zis.getNextEntry()) != null) {
			File lotlZipDir = new File(casesFolder, entry.getName().replace(".zip", ""));
			lotlZipDir.mkdir();
			unzip(zis, lotlZipDir);
		}
		zis.close();

		// Parse files
		List<File> folders = Arrays.asList(new File(casesFolder).listFiles());
		Collections.sort(folders);

		for (File folder : folders) {
			parseFolder(folder);
		}
	}

	private static void unzip(InputStream inputStream, File targetDir) throws IOException {
		ZipInputStream zis = new ZipInputStream(inputStream);
		ZipEntry entry;
		while ((entry = zis.getNextEntry()) != null) {
			FileOutputStream fos = new FileOutputStream(new File(targetDir, entry.getName()));
			transfer(zis, fos);
			fos.close();
		}
	}

	/**
	 * Test cases related to a single lotl
	 * 
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 */
	private void parseFolder(File lotlFolder) throws IOException, ParserConfigurationException, SAXException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException {
		// First, get the LOTL configuration
		String lotlUrl = getFileContent(lotlFolder, LOTL_URL_FILTER);
		File lotlP12 = getFile(lotlFolder, LOTL_P12_FILTER);
		String lotlP12Password = getFileContent(lotlFolder, LOTL_P12_PASSWORD_FILTER);

		LOTLConfig lotlConfig = new LOTLConfig(lotlUrl, lotlP12, lotlP12Password);

		// Iterate on cases
		List<File> testFiles = Arrays.asList(lotlFolder.listFiles(TEST_FILE_FILTER));
		Collections.sort(testFiles);

		for (File testFile : testFiles) {
			if (testFile.length() == 0) {
				// Some test files are empty in Validation test cases... Ignore them
				logger.warn("Test file " + testFile.getName() + " is empty. Ignoring.");

			} else {
				// Get conclusion filename from test filename
				String conclusionFileName = testFile.getName().replace(TEST_FILE_SUFFIX, CONCLUSION_FILE_SUFFIX);
				
				String expectedConclusion = getFileContent(new File(lotlFolder, conclusionFileName));

				// Add test at the end of list : tests with same LOTL config will be contiguous.
				validationTests.add(new ValidationTest(testFile, expectedConclusion, lotlConfig));
			}
		}
	}

	/**
	 * A file suffix filter
	 * 
	 * @author nro
	 */
	private static class FileSuffixFilter implements FileFilter {
		private final String suffix;

		public FileSuffixFilter(String suffix) {
			this.suffix = suffix;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public boolean accept(File pathname) {
			return pathname.getName().endsWith(suffix);
		}

		/**
		 * Useful in case of error, to display the filter config
		 */
		@Override
		public String toString() {
			return "Filter by suffix = " + suffix;
		}
	}

	/**
	 * Obtain file matching filter in given folder.
	 * 
	 * Will fail if no file, or many files match the filter
	 */
	private File getFile(File folder, FileFilter filter) {
		File[] files = folder.listFiles(filter);
		if (files.length != 1) {
			fail("In folder " + folder.getAbsolutePath() + ", " + filter.toString() + " returned " + files.length
					+ " file(s) while 1 was expected");
		}

		return files[0];
	}

	/**
	 * Obtain the content file matching filter in given folder.
	 * 
	 * Will fail if no file, or many files match the filter
	 * 
	 * @throws IOException
	 */
	private String getFileContent(File folder, FileFilter filter) throws IOException {
		File file = getFile(folder, filter);
		return getFileContent(file);
	}

	/**
	 * Get the content of a file as a string
	 * 
	 * @param file
	 * @return
	 * @throws IOException
	 */
	private String getFileContent(File file) throws IOException {
		FileInputStream fis = new FileInputStream(file);
		try {
			return getString(fis);
		} finally {
			fis.close();
		}
	}

	public List<ValidationTest> getValidationTests() {
		return validationTests;
	}

	/**
	 * A unit test
	 * 
	 * @author nro
	 *
	 */
	public static class ValidationTest {
		private final File testFile;
		private final String expectedConclusion;
		private final LOTLConfig lotlConfig;

		public ValidationTest(File testFile, String expectedConclusion, LOTLConfig lotlConfig) {
			this.testFile = testFile;
			this.expectedConclusion = expectedConclusion;
			this.lotlConfig = lotlConfig;
		}

		public File getTestFile() {
			return testFile;
		}

		public String getExpectedConclusion() {
			return expectedConclusion;
		}

		public LOTLConfig getLotlConfig() {
			return lotlConfig;
		}

		@Override
		public String toString() {
			return "[Validation Test " + this.testFile.getName() + "]";
		}
	}

	/**
	 * LOTL configuration. Implements equal (Two LOTL are equal if they have same
	 * URL)
	 * 
	 * @author nro
	 *
	 */
	public static class LOTLConfig {
		private final String lotlUrl;
		private final File lotlP12;
		private final String lotlP12Password;

		public LOTLConfig(String lotlUrl, File lotlP12, String lotlP12Password)
				throws IOException, ParserConfigurationException, SAXException, KeyStoreException,
				NoSuchAlgorithmException, CertificateException {
			this.lotlUrl = lotlUrl;
			this.lotlP12 = lotlP12;
			this.lotlP12Password = lotlP12Password;

			// Fix P12 if we are asked to (c.f. comment on FIX_LOTL_P12)
			if (FIX_LOTL_P12) {
				this.fixP12();
			}
		}

		public String getLotlUrl() {
			return lotlUrl;
		}

		public File getLotlP12() {
			return lotlP12;
		}

		public String getLotlP12Password() {
			return lotlP12Password;
		}

		/**
		 * Two LOTL have same hashcode if they have same URL
		 */
		@Override
		public int hashCode() {
			return this.lotlUrl.hashCode();
		}

		/**
		 * Two LOTL are equal if they have same URL
		 */
		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof LOTLConfig)) {
				return false;
			}
			return this.lotlUrl.equals(((LOTLConfig) obj).lotlUrl);
		}

		@Override
		public String toString() {
			return "[LOTL at endpoint " + this.lotlUrl + "]";
		}

		/**
		 * Fix the P12 to reflect the actual certificate used to sign LOTL.
		 * 
		 * @throws IOException
		 * @throws ParserConfigurationException
		 * @throws SAXException
		 * @throws KeyStoreException
		 * @throws CertificateException
		 * @throws NoSuchAlgorithmException
		 */
		private void fixP12() throws IOException, ParserConfigurationException, SAXException, KeyStoreException,
				NoSuchAlgorithmException, CertificateException {
			// Download LOTL
			URL url = new URL(this.lotlUrl);
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();

			// Unexpected response ?
			if (HttpURLConnection.HTTP_OK != connection.getResponseCode()) {
				fail("Unexpected response while downloading LOTL " + this.lotlUrl + " for fixing P12. Response code : "
						+ connection.getResponseCode() + ". Body : " + getString(connection.getInputStream()));
			}

			// Extract the certificate used to sign
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document document = builder.parse(connection.getInputStream());
			Element root = document.getDocumentElement();
			Element signature = getFirstChild(root, "ds:Signature");
			Element keyInfo = getFirstChild(signature, "ds:KeyInfo");
			Element x509Data = getFirstChild(keyInfo, "ds:X509Data");
			Element x509Certificate = getFirstChild(x509Data, "ds:X509Certificate");
			String base64 = x509Certificate.getTextContent();
			byte[] certBytes = Base64.getDecoder().decode(base64);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

			Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

			KeyStore keystore = KeyStore.getInstance("PKCS12");
			// Initialize.
			keystore.load(null, this.lotlP12Password.toCharArray());

			keystore.setCertificateEntry("fixed-lotl-certif", certificate);

			// Overwrite
			FileOutputStream fos = new FileOutputStream(this.lotlP12);
			keystore.store(fos, this.lotlP12Password.toCharArray());
			fos.close();
		}
	}

	/**
	 * Obtain first child of given element with given name. null if not found
	 */
	private static Element getFirstChild(Element element, String name) {
		for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
			if (child instanceof Element && name.equals(child.getNodeName())) {
				return (Element) child;
			}
		}
		return null;
	}

	/**
	 * Reads from an inputStream and returns a string; uses default charset for
	 * stream -> char conversion. Closes inputStream.
	 * 
	 * @throws IOException
	 */
	private static String getString(InputStream inputStream) throws IOException {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try {
			transfer(inputStream, baos);

			return baos.toString(); // Default encoding

		} finally {
			inputStream.close();
		}
	}

	/**
	 * Transfer inputStream to outputStream (InputStream.transferTo is not available
	 * prior to java 9). Does not close input or output.
	 * 
	 * @param inputStream
	 * @param outputStream
	 * @throws IOException
	 */
	private static void transfer(InputStream inputStream, OutputStream outputStream) throws IOException {
		byte[] buf = new byte[4096];
		int length;
		while ((length = inputStream.read(buf)) > 0) {
			outputStream.write(buf, 0, length);
		}
	}
}
