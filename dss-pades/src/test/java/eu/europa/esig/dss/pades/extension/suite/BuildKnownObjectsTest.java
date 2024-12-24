/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentAnalyzer;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BuildKnownObjectsTest extends PKIFactoryAccess {

	/*
	 * Duplicate streams
	 * CRLs: 27 = 21
	 * 28 = 22
	 * Certificates: 20=26
	 */
	@Test
	void buildKnownObjects() {

		DSSDocument dssDocument = new InMemoryDocument(
				getClass().getResourceAsStream("/validation/dss-1696/Test.signed_Certipost-2048-SHA512.extended.pdf"));
		PDFDocumentAnalyzer pdfDocumentAnalyzer = new PDFDocumentAnalyzer(dssDocument);

		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();

		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R] -> 20 30
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R]>> -> 21 22 29

		List<AdvancedSignature> signatures = pdfDocumentAnalyzer.getSignatures();
		assertEquals(1, signatures.size());

		PAdESSignature padesSignature = (PAdESSignature) signatures.get(0);
		PdfDssDict dssDictionary = padesSignature.getDssDictionary();
		assertEquals(3, dssDictionary.getCERTs().size());
		assertEquals(5, dssDictionary.getCRLs().size());

		certificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert());
		certificateVerifier.setAlertOnUncoveredPOE(new LogOnStatusAlert());
		certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());

		CertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID9TCCAt2gAwIBAgIQF3Dg4iQuLQxzMPFRPs8rqDANBgkqhkiG9w0BAQsFADByMSMwIQYDVQQDExpVbml2ZXJzaWduIFRpbWVzdGFtcGluZyBDQTEcMBoGA1UECxMTMDAwMiA0MzkxMjkxNjQwMDAyNjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxCzAJBgNVBAYTAkZSMB4XDTEwMDUwNjA5MzA1OVoXDTIwMDUwNjA5MzA1OVowcjEjMCEGA1UEAxMaVW5pdmVyc2lnbiBUaW1lc3RhbXBpbmcgQ0ExHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxIDAeBgNVBAoTF0NyeXB0b2xvZyBJbnRlcm5hdGlvbmFsMQswCQYDVQQGEwJGUjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMF2r8Q+dqh3iA6fPMn0bOw50sKTsCPCocGVNPf75b6dERmkuiXj48/M6poFaPxV96Y01B8LjTUFYGQr6Vbf/15HvVskV6ZSTb8PXNZef6vv7681qnMp7NZVyrWO9zjg4NcZ9qVKFlzZe2NCGHAZi+5z7Y4Phnvg7XdLu0B92oERAIoconTcsHO6BSg9nhv0c+xDsUNdRKF1groYZtAwNO1L1j5kLY3PukPPKa0+uyrJ8j56mGGUGWKaZxLuKafn5M3tYMousgKxQ/5cDHnjntTFBXfm7+Jg0PeiJP6boM2nZDTcnPBt+wvXzo27L4GV0GvZfoi0CVa27hkURRSnsJcCAwEAAaOBhjCBgzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjBBBgNVHSAEOjA4MDYGCisGAQQB+0sFAQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2RvY3MudW5pdmVyc2lnbi5ldS8wHQYDVR0OBBYEFOzknxQd8GYKOfVELMDFf8PMwaW1MA0GCSqGSIb3DQEBCwUAA4IBAQAySgYJxVNszlupDmOTfKcSXRohKwxfgv/wVJhH7ypgqX9z+KM8sh0FDrO2TbEyU/rnpJwauTUwPoa40plvLcBV3zcsA72mzG9fgjmftj0D5Lxhkqsn7B13YOP/tlqoe4f1jyfysxc/JpoBKXklJIBMW5DAbPxZPehVRpBJqrd0ZJNhKZFbBZvVIZ7KO5PX10k1016yiB8LIuASeJfGMHlzvX0qorvl+98g868vQQB6xyMC8WcikEVsVrTBXnNsdD2F6EkC+HJ88qT5XfUGMxq88hvufpwfD3kTkqDm5RDhn0a0o8eIRlze2XopYWz17GWyUVyawoZcEfFYlDxjbo1p"));
		trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID/zCCAuegAwIBAgIQP8umE0YUpE/yhLiMgaeopDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJGUjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxKDAmBgNVBAMTH1VuaXZlcnNpZ24gVGltZXN0YW1waW5nIENBIDIwMTUwHhcNMTUwMTI5MTQwMzE1WhcNMjUwMTI5MTQwMzE1WjB3MQswCQYDVQQGEwJGUjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxKDAmBgNVBAMTH1VuaXZlcnNpZ24gVGltZXN0YW1waW5nIENBIDIwMTUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYc1VJ69W70ojewtKbCLZ+P8bDAVJ1qujzgIZEvm15GYX7Jp+Hl9rwxBdswSZ8S5A/x+0j6YMOHH0Z+iGl649+0GGX1gdAuovQKShsvLSzD/waINxkXXTVXpAW3V4dnCgcb3qaV/pO9NTk/sdRJxM8lUtWuD7TEAfLzz7Ucl6gBjDTA0Gz+AtUkNWPcofCWuDfiSDOOpyKwSxovde6SRwHdTXXIiC2Dphffjrr74MvLb0La5JAUwmJLIH42j/frgZeWk148wLMwBW+lvrIJtPz7eHNtTlNfQLrmmJHW4l+yvTsdJJDs7QYtfzBTNg1zqV8eo/hHxFTFJ8/T9wTmENJAgMBAAGjgYYwgYMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwQQYDVR0gBDowODA2BgorBgEEAftLBQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9kb2NzLnVuaXZlcnNpZ24uZXUvMB0GA1UdDgQWBBT6Te1XO70/85Ezmgs5pH9dEt0HRjANBgkqhkiG9w0BAQsFAAOCAQEAc7ud6793wgdjR8Xc1L47ufdVTamI5SHfOThtROfn8JL0HuNHKdRgv6COpdjtt6RwQEUUX/km7Q+Pn+A2gA/XoPfqD0iMfP63kMMyqgalEPRv+lXbFw3GSC9BQ9s2FL7ScvSuPm7VDZhpYN5xN6H72y4z7BgsDVNhkMu5AiWwbaWF+BHzZeiuvYHX0z/OgY2oH0hluovuRAanQd4dOa73bbZhTJPFUzkgeIzOiuYS421IiAqsjkFwu3+k4dMDqYfDKUSITbMymkRDszR0WGNzIIy2NsTBcKYCHmbIV9S+165i8YjekraBjTTSbpfbty87A1S53CzA2EN1qnmQPwqFfg=="));
		trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID3jCCAsagAwIBAgILBAAAAAABBVJkxCUwDQYJKoZIhvcNAQEFBQAwXDELMAkGA1UEBhMCQkUxHDAaBgNVBAoTE0NlcnRpcG9zdCBzLmEuL24udi4xLzAtBgNVBAMTJkNlcnRpcG9zdCBFLVRydXN0IFByaW1hcnkgUXVhbGlmaWVkIENBMB4XDTA1MDcyNjEwMDAwMFoXDTIwMDcyNjEwMDAwMFowXDELMAkGA1UEBhMCQkUxHDAaBgNVBAoTE0NlcnRpcG9zdCBzLmEuL24udi4xLzAtBgNVBAMTJkNlcnRpcG9zdCBFLVRydXN0IFByaW1hcnkgUXVhbGlmaWVkIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAriDSeNuaoHKcBFIlLG1S2NcniTOg4bLV+zB1ay1/HGeODucfEt8XeRi7tBtv+D11G55nN/Dx+g917YadAwShKHAtPLJroHNR4zWpdKUIPpSFJzYqqnJk/HfudpQccuu/Msd3A2olggkFr19gPH+sG7yS6Dx0Wc7xfFQtOK6W8KxvoTMMIVoBuiMgW6CGAtVT3EkfqDKzrztGO7bvnzmzOAvneor2KPmnb1ApyHlYi0nSpdiFflbxaRV4RBE116VUPqtmJdLb4xjxLivicSMJN2RDQnQylnfel6LploacJUQJ1AGdUX4ztwlE5YCXDWRbdxiXpUupnhCdh/pWp88KfQIDAQABo4GgMIGdMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTwePkHdxC73B6hrnn7MBDbxjT4FzBIBgNVHSAEQTA/MD0GCQOQDgcBAAECADAwMC4GCCsGAQUFBwIBFiJodHRwOi8vd3d3LmUtdHJ1c3QuYmUvQ1BTL1FOY2VydHMgMBEGCWCGSAGG+EIBAQQEAwIABzANBgkqhkiG9w0BAQUFAAOCAQEAbOHYX3RY6XBJ1soNLFjaymS2UU/DBmQB6YpzHZ7PRni/O4WG4j1KGJQqgXdvgvhv9O4i/J0YIXJguxiAgpX7+feVJIFmwbXDtdK2dos7gVy4oQ4rARSLgAlA7vhgTBnkF80nAbNjEgWkCMm0v55QTrXeD5IzZnXQPecjfOolcXz+Pi42eaHlKVAjNQWVeLufeWTcV0gnLOJcM83Cu35od6cvo0kXcuEAhGt9eq85CyzV2FdkMmyECmp2OtOszZ2x5zfc7AwvxVdg34j1Q7EBZCa0J4IQsqNQ75fmf7+Rh7PbkKkq4no0bHNJ9OiNLmuK3aGKf2PQv1ger8w/klAt0Q=="));
		trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIEPzCCA6igAwIBAgIEBycUMzANBgkqhkiG9w0BAQUFADB1MQswCQYDVQQGEwJVUzEYMBYGA1UEChMPR1RFIENvcnBvcmF0aW9uMScwJQYDVQQLEx5HVEUgQ3liZXJUcnVzdCBTb2x1dGlvbnMsIEluYy4xIzAhBgNVBAMTGkdURSBDeWJlclRydXN0IEdsb2JhbCBSb290MB4XDTA3MDMyMTE0MjAxN1oXDTE3MDMwNzE0MTk0M1owXDELMAkGA1UEBhMCQkUxHDAaBgNVBAoTE0NlcnRpcG9zdCBzLmEuL24udi4xLzAtBgNVBAMTJkNlcnRpcG9zdCBFLVRydXN0IFByaW1hcnkgUXVhbGlmaWVkIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAriDSeNuaoHKcBFIlLG1S2NcniTOg4bLV+zB1ay1/HGeODucfEt8XeRi7tBtv+D11G55nN/Dx+g917YadAwShKHAtPLJroHNR4zWpdKUIPpSFJzYqqnJk/HfudpQccuu/Msd3A2olggkFr19gPH+sG7yS6Dx0Wc7xfFQtOK6W8KxvoTMMIVoBuiMgW6CGAtVT3EkfqDKzrztGO7bvnzmzOAvneor2KPmnb1ApyHlYi0nSpdiFflbxaRV4RBE116VUPqtmJdLb4xjxLivicSMJN2RDQnQylnfel6LploacJUQJ1AGdUX4ztwlE5YCXDWRbdxiXpUupnhCdh/pWp88KfQIDAQABo4IBbzCCAWswEgYDVR0TAQH/BAgwBgEB/wIBATBTBgNVHSAETDBKMEgGCSsGAQQBsT4BADA7MDkGCCsGAQUFBwIBFi1odHRwOi8vd3d3LnB1YmxpYy10cnVzdC5jb20vQ1BTL09tbmlSb290Lmh0bWwwDgYDVR0PAQH/BAQDAgEGMIGJBgNVHSMEgYEwf6F5pHcwdTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD0dURSBDb3Jwb3JhdGlvbjEnMCUGA1UECxMeR1RFIEN5YmVyVHJ1c3QgU29sdXRpb25zLCBJbmMuMSMwIQYDVQQDExpHVEUgQ3liZXJUcnVzdCBHbG9iYWwgUm9vdIICAaUwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL3d3dy5wdWJsaWMtdHJ1c3QuY29tL2NnaS1iaW4vQ1JMLzIwMTgvY2RwLmNybDAdBgNVHQ4EFgQU8Hj5B3cQu9weoa55+zAQ28Y0+BcwDQYJKoZIhvcNAQEFBQADgYEALyAT1dejn45tPABj1Lp0QfUo1TJAvE9NDcMVcbe8bXYNOlmFaG7jHvUcSBkODYbuHzc6Ziwu0IEbb97Xt7JuY3E7XUsCZVEM0CVAc3G/XR16eVoAB95VuHoaxYaDDaAEoG2rAHOEAUsvpGp3MFKA3QDHDyMI5cAVsNUI1r5jUgQ="));
		certificateVerifier.setTrustedCertSources(trustedCertSource);

		PAdESService padesService = new PAdESService(certificateVerifier);
		padesService.setTspSource(getGoodTsa());

		PAdESSignatureParameters parameters = new PAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		DSSDocument extendSignature = padesService.extendDocument(dssDocument, parameters);
		
		pdfDocumentAnalyzer = new PDFDocumentAnalyzer(extendSignature);
		pdfDocumentAnalyzer.setCertificateVerifier(getOfflineCertificateVerifier());

		signatures = pdfDocumentAnalyzer.getSignatures();
		assertEquals(1, signatures.size());

		PAdESSignature pades = (PAdESSignature) signatures.get(0);

		dssDictionary = pades.getDssDictionary();
		Map<PdfObjectKey, CRLBinary> crlMap = dssDictionary.getCRLs();
		assertEquals(3, crlMap.size()); // we don't collect newer CRLS

		// original duplicates must be referenced
		assertContainsObjectWithKey(crlMap.keySet(), 21);
		assertContainsObjectWithKey(crlMap.keySet(), 22);
		assertContainsObjectWithKey(crlMap.keySet(), 29);

		Map<PdfObjectKey, CertificateToken> certMap = dssDictionary.getCERTs();
		assertContainsObjectWithKey(certMap.keySet(), 20);
		assertContainsObjectWithKey(certMap.keySet(), 30);

	}

	private void assertContainsObjectWithKey(Collection<PdfObjectKey> objectKeys, long objectNumber) {
		assertTrue(objectKeys.stream().anyMatch(k -> objectNumber == k.getNumber()));
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
