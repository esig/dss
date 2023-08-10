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
package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.xades.definition.XAdESPath;
import eu.europa.esig.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class XAdES132OnlyTest {

	@Test
	public void test() {

		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setAIASource(null);
		FileDocument xmlDocument = new FileDocument("src/test/resources/signature-pool/signedXmlXadesB.xml");

		// tag::demo[]
		// import eu.europa.esig.dss.validation.reports.Reports;
		// import eu.europa.esig.dss.xades.definition.XAdESPaths;
		// import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;
		// import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
		// import java.util.List;

		// Initialize document validator
		XMLDocumentValidator xmlDocumentValidator = new XMLDocumentValidator(xmlDocument);
		xmlDocumentValidator.setCertificateVerifier(cv);

		// Restrict the current XMLDocumentValidator to XAdES 1.3.2 (and 1.4.1 for
		// archival timestamps)
		List<XAdESPath> xadesPathsHolders = xmlDocumentValidator.getXAdESPathsHolder();
		xadesPathsHolders.clear();
		xadesPathsHolders.add(new XAdES132Path());

		Reports reports = xmlDocumentValidator.validateDocument();
		// end::demo[]

		assertNotNull(reports);

		CertificateToken rootCertificate = DSSUtils.loadCertificateFromBase64EncodedString("MIIFZzCCA0+gAwIBAgIJAOmNoGKXF3NoMA0GCSqGSIb3DQEBCwUAMCsxDDAKBgNVBAoTA0RTUzELMAkGA1UEBhMCQUExDjAMBgNVBAMTBVJDQSBBMB4XDTEzMTIwMjE2NTEyNloXDTMzMTEyNzE2NTEyNlowKzEMMAoGA1UEChMDRFNTMQswCQYDVQQGEwJBQTEOMAwGA1UEAxMFUkNBIEEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDAeMx057o0sWoKnkbI65ZJZBoSmKYzDvSCY7BEm78Ofh9GLz/IQqc6dzWfRG/BtLGa2XRqkcECbEQFHrP4fShzFQP5gAPge+DFOWmoWntOrqz5L23hOoz0qw0bS6yWQcGk33XH89ecGUrRsKYk0J6XwhjvJ/6ipx4SLY8BBjzHldo6OvrjXqlcDVapUBssyujpG5pMjnE5s5/SKmZcGnie3cr96rRTCh+8qhv+XHsGJ7iLTbUXNJijpg80p2TX4q2r9JajgsXGTI+koLjQr7Clchatzzu/HUtHrSBXBN4RnopY8dZVmYJ8ndXE8M6HXn4zOoNW2iolDY72Z5p4RPAiGdq/OZv0nrawX28pcWl42g1sHd4eBkHdGdnT5JReukpXBYJ4dP2niM9xYXeokszYeOKq5ZhSNsqr9/5DlSrGvbmAcki0KCcLp7F7pXMO3iyc52IYFyCPM7CZDlCh9EGg25YNVyV8YAjHT9f/pT60SyIWIw2ZbG82FE0I/1iUsfvy+gAxjXoxAn5T5C5vW9LZR6jdEE3A0mDd5OqVjOsfGi1fg1LcgltTmlg6z4cKXGngcYYrsZ5tgS8htRi58YjyZx12fJMoIt3HgqSpfwEPE0DGdahrMtoAvTy5zKENuCWBCAAkhe/tQ7IzI4uBjb5tLLI0zrMq8Xf6h+0+YDRc0QIDAQABo4GNMIGKMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFNs4LU6iKHMD5Syc2jYbHEkOxpQUMFsGA1UdIwRUMFKAFNs4LU6iKHMD5Syc2jYbHEkOxpQUoS+kLTArMQwwCgYDVQQKEwNEU1MxCzAJBgNVBAYTAkFBMQ4wDAYDVQQDEwVSQ0EgQYIJAOmNoGKXF3NoMA0GCSqGSIb3DQEBCwUAA4ICAQAwfOKZqRgZJsY6gjC9RZgZLjzK4cfvfDwXWJEUKcTDZUIm8MUKOpw+4DvngzmWKhrzpznFd5X/fLjKlNQrUjeNdW1KtsDiNFrENVexpNK/2gKbbsqt1Vhml5ZEkf0nHc8BWnKayvbke366D0Gq8pdOFQyBr3qp2g/Gf4aXwjcMRG5f/tuU75IGNCDOYureXuNHZzAnxBZCg9j5un27+mpH8ACS0NiYuM0qd3cytrZPmdhkfE+aDTPnCyvtUw2Fa5nNTRqZ7e3kyj/+jvQCn3p9wd7ESSONR/twWmmT4JtU3G6FRJwAc8iQUErKjBBq7T7zu0M86nR4y3hKFk2HqQx6XcRRGUnSe4j3jUNlaSKOqHavZu3gkLt1T6VDXOgKa2Tw8NkVF2UXe6tjikpUGCxKLXsAIaB9zL7OGwjFyuttzNqlQd9zQ5fYFPzZ2LAhvZtb0q+gkLnKlsOoqtuJbEy9uY4SVItDT/rRr2yuDr9E866jsPuCjPYZxv02Mx0mEdWSmAy2RzeSq5/iSpVF4MbyPgoIfF2Zr8MZG1Jr391JNvpFp8vP90x/OjK2RPWYuHZyWowQnUkHlzWR/qwK/VvbcB9XjgYz/z5rFO8/l8wZ7x/BZKOMRtUFOamhYs/AP8wIH3GQReJUyESz9I/tCN3OI3rhoQ2wQvxMA8Rl5ETGhw==");

		// tag::trustAnchors[]
		// import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
		// import eu.europa.esig.dss.validation.CertificateVerifier;
		// import eu.europa.esig.dss.validation.CommonCertificateVerifier;
		// import eu.europa.esig.dss.validation.SignedDocumentValidator;

		// Initialize document validator
		DocumentValidator documentValidator = SignedDocumentValidator.fromDocument(xmlDocument);

		// Initialize CertificateVerifier
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();

		// Create trusted certificate source and provide a collection of certificates you trust
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(rootCertificate);

		// Provide the CertificateVerifier to a document validator
		documentValidator.setCertificateVerifier(certificateVerifier);
		// end::trustAnchors[]

		reports = documentValidator.validateDocument();
		assertNotNull(reports);

	}

}
