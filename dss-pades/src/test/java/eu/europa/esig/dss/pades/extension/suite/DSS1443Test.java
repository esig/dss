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
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS1443Test extends PKIFactoryAccess {

	@Test
	public void testSigWithAttached() {

		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-1443.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);

		CertificateVerifier certificateVerifier = getCertificateVerifier();
		certificateVerifier.setAlertOnExpiredCertificate(new LogOnStatusAlert(Level.WARN));

		validator.setCertificateVerifier(certificateVerifier);
		Reports reports = validator.validateDocument();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureLevel.PAdES_BASELINE_T, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));

		PAdESService service = new PAdESService(certificateVerifier);
		service.setTspSource(getCompositeTsa());

		PAdESSignatureParameters parameters = new PAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		DSSDocument extendDocument = service.extendDocument(dssDocument, parameters);

		validator = SignedDocumentValidator.fromDocument(extendDocument);
		validator.setCertificateVerifier(certificateVerifier);
		reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getAllSignatures().size());

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(2, signature.getDocumentTimestamps().size());
		assertEquals(2, signature.getTLevelTimestamps().size());
		assertEquals(1, signature.getALevelTimestamps().size());

		List<TimestampWrapper> allTimestamps = diagnosticData.getTimestampList();
		assertEquals(2, allTimestamps.size());

		for (TimestampWrapper timestampWrapper : allTimestamps) {
			assertEquals(TimestampType.DOCUMENT_TIMESTAMP, timestampWrapper.getType());
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			
			assertNotNull(timestampWrapper.getSignatureDictionaryType());
			assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getSignatureFieldNames()));
			assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getSignatureByteRange()));
			assertNotNull(timestampWrapper.getFilter());
			assertNotNull(timestampWrapper.getSubFilter());
		}
	}

	private CertificateVerifier getCertificateVerifier() {
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setAlertOnExpiredCertificate(new LogOnStatusAlert(Level.WARN));

		certificateVerifier.setCrlSource(getCompositeCRLSource());

		CertificateSource trustedCertSource = getTrustedCertificateSource();
		trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID6TCCAtGgAwIBAgICEsMwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCTFUxFjAUBgNVBAoTDUx1eFRydXN0IHMuYS4xHTAbBgNVBAMTFEx1eFRydXN0IEdsb2JhbCBSb290MB4XDTE0MDUyODEzMDkxOFoXDTIwMDUyODEzMDkxOFowTjELMAkGA1UEBhMCTFUxFjAUBgNVBAoTDUx1eFRydXN0IFMuQS4xJzAlBgNVBAMTHkx1eFRydXN0IEdsb2JhbCBRdWFsaWZpZWQgQ0EgMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMRaetIHqOXl0cMdtVuB3StPlDTeneHMgenp4W/5u4GimFETER3Msj9C6JeAg9H63Az/JpPdGjVWpREZ4goR29Y2Ys1S0kyW9ONFKwyDHm2tU6nyTnx9hVNDDkA4DMNZuf3UIo3J7xaTae1u5ALlIh+g4aPeiYtB4XZlJPGvy3mmQ6020jqQWgeCRVCl91p1HLu6oPZ6xp+wy2qWzhzn7jo81Y8S2g+cD/qen2jphIae8PRLtEjuMLREcu/Rt03PDfxxi2usnSb1djQImYEL/R6I7VgK+UkNXYy+vasXOqWclZ7oMeA6iMt4WkjEKWsKf60eFlVW8J66vA//IdY7IUsCAwEAAaOB2jCB1zAPBgNVHRMECDAGAQH/AgEAMEMGA1UdIAQ8MDowOAYIK4ErAQEBCgMwLDAqBggrBgEFBQcCARYeaHR0cHM6Ly9yZXBvc2l0b3J5Lmx1eHRydXN0Lmx1MAsGA1UdDwQEAwIBBjAfBgNVHSMEGDAWgBQXFYWJCS8kh28/HRvk8pZ5g0gTzjAyBgNVHR8EKzApMCegJaAjhiFodHRwOi8vY3JsLmx1eHRydXN0Lmx1L0xUR1JDQS5jcmwwHQYDVR0OBBYEFO+Wv31lOlW00nD4DOxK4vMnBppSMA0GCSqGSIb3DQEBCwUAA4IBAQCBkOXfYtTOMb853+Oq49NENBFTcjqohYLyvc/w8gisbbe8OPdRfLam+PAkYKfyoy77R78E8Ypg5R9ASxqFt5lEgFADE022+lqs5GNpOVIoit+WCtC4k19SkyOvypqZZApEEfc1VxadqhwwsdJRTt+aVhuItuUo4GGNGTub+y/bs6IGUpNnuWibrqevc2jaG9YYQPGfu9WUtj5znQ+0VdH6wPXfumhHag4Ipl8aBh5kXYEDFpgINdIfbBNq3ULKHNdzdCZj5bJZVxxbW1qC0BQ1UD1o2KoiLQy9G15UErAQHx1BbVGA+eSbZe7Fpy1Va3K0z76usMSSOBf7YlJ7e0Hq"));
		trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID/zCCAuegAwIBAgIQP8umE0YUpE/yhLiMgaeopDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJGUjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxKDAmBgNVBAMTH1VuaXZlcnNpZ24gVGltZXN0YW1waW5nIENBIDIwMTUwHhcNMTUwMTI5MTQwMzE1WhcNMjUwMTI5MTQwMzE1WjB3MQswCQYDVQQGEwJGUjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxKDAmBgNVBAMTH1VuaXZlcnNpZ24gVGltZXN0YW1waW5nIENBIDIwMTUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYc1VJ69W70ojewtKbCLZ+P8bDAVJ1qujzgIZEvm15GYX7Jp+Hl9rwxBdswSZ8S5A/x+0j6YMOHH0Z+iGl649+0GGX1gdAuovQKShsvLSzD/waINxkXXTVXpAW3V4dnCgcb3qaV/pO9NTk/sdRJxM8lUtWuD7TEAfLzz7Ucl6gBjDTA0Gz+AtUkNWPcofCWuDfiSDOOpyKwSxovde6SRwHdTXXIiC2Dphffjrr74MvLb0La5JAUwmJLIH42j/frgZeWk148wLMwBW+lvrIJtPz7eHNtTlNfQLrmmJHW4l+yvTsdJJDs7QYtfzBTNg1zqV8eo/hHxFTFJ8/T9wTmENJAgMBAAGjgYYwgYMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwQQYDVR0gBDowODA2BgorBgEEAftLBQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9kb2NzLnVuaXZlcnNpZ24uZXUvMB0GA1UdDgQWBBT6Te1XO70/85Ezmgs5pH9dEt0HRjANBgkqhkiG9w0BAQsFAAOCAQEAc7ud6793wgdjR8Xc1L47ufdVTamI5SHfOThtROfn8JL0HuNHKdRgv6COpdjtt6RwQEUUX/km7Q+Pn+A2gA/XoPfqD0iMfP63kMMyqgalEPRv+lXbFw3GSC9BQ9s2FL7ScvSuPm7VDZhpYN5xN6H72y4z7BgsDVNhkMu5AiWwbaWF+BHzZeiuvYHX0z/OgY2oH0hluovuRAanQd4dOa73bbZhTJPFUzkgeIzOiuYS421IiAqsjkFwu3+k4dMDqYfDKUSITbMymkRDszR0WGNzIIy2NsTBcKYCHmbIV9S+165i8YjekraBjTTSbpfbty87A1S53CzA2EN1qnmQPwqFfg=="));
		certificateVerifier.setTrustedCertSources(trustedCertSource);

		return certificateVerifier;
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
