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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReportFacade;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBException;
import javax.xml.transform.TransformerException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.GregorianCalendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CertificateValidatorTest {

	@Test
	public void test() throws JAXBException, IOException, SAXException, TransformerException {
		CertificateValidator cv = CertificateValidator.fromCertificate(DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer")));
		cv.setCertificateVerifier(new CommonCertificateVerifier());

		CertificateReports reports = cv.validate();

		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getXmlDiagnosticData());
		assertNotNull(reports.getDetailedReportJaxb());
		assertNotNull(reports.getXmlDetailedReport());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getXmlSimpleReport());

		SimpleCertificateReportFacade simpleCertificateReportFacade = SimpleCertificateReportFacade.newFacade();
		String marshalled = simpleCertificateReportFacade.marshall(reports.getSimpleReportJaxb(), true);
		assertNotNull(marshalled);
		assertNotNull(simpleCertificateReportFacade.generateHtmlReport(marshalled));
		assertNotNull(simpleCertificateReportFacade.generateHtmlReport(reports.getSimpleReportJaxb()));

		DetailedReportFacade detailedReportFacade = DetailedReportFacade.newFacade();
		String marshalledDetailedReport = detailedReportFacade.marshall(reports.getDetailedReportJaxb(), true);
		assertNotNull(marshalledDetailedReport);
		assertNotNull(detailedReportFacade.generateHtmlReport(marshalledDetailedReport));
		assertNotNull(detailedReportFacade.generateHtmlReport(reports.getDetailedReportJaxb()));
	}

	@Test
	public void testCertNull() {
		NullPointerException exception = assertThrows(NullPointerException.class,
				() -> CertificateValidator.fromCertificate(null));
		assertEquals("The certificate is missing", exception.getMessage());
	}

	@Test
	public void testPolicyNull() {
		CertificateValidator cv = CertificateValidator
				.fromCertificate(DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer")));
		cv.setCertificateVerifier(new CommonCertificateVerifier());
		NullPointerException exception = assertThrows(NullPointerException.class, () -> cv.validate(null));
		assertEquals("The validation policy is missing", exception.getMessage());
	}

	@Test
	public void testCustomDate() {
		CertificateValidator cv = CertificateValidator.fromCertificate(DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer")));
		cv.setCertificateVerifier(new CommonCertificateVerifier());
		GregorianCalendar gregorianCalendar = new GregorianCalendar(2019, 1, 1);
		cv.setValidationTime(gregorianCalendar.getTime());
		CertificateReports certificateReports = cv.validate();
		DiagnosticData diagnosticData = certificateReports.getDiagnosticData();
		assertEquals(gregorianCalendar.getTime(), diagnosticData.getValidationDate());
	}

	@Test
	public void testPSD2() {
		CertificateToken cert = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");

		CertificateValidator cv = CertificateValidator.fromCertificate(cert);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setAIASource(null);
		cv.setCertificateVerifier(certificateVerifier);

		CertificateReports reports = cv.validate();
		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getXmlDiagnosticData());
		assertNotNull(reports.getDetailedReportJaxb());
		assertNotNull(reports.getXmlDetailedReport());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getXmlSimpleReport());

		CertificateWrapper certificateWrapper = reports.getDiagnosticData().getUsedCertificateById(cert.getDSSIdAsString());
		assertNotNull(certificateWrapper);
		assertNotNull(certificateWrapper.getPSD2Info());
		assertNotNull(certificateWrapper.getPSD2Info().getNcaId());
		assertNotNull(certificateWrapper.getPSD2Info().getNcaName());
		assertNotNull(certificateWrapper.getPSD2Info().getRoleOfPSPNames());
		assertNotNull(certificateWrapper.getPSD2Info().getRoleOfPSPOids());
	}

	@Test
	public void qcStatementsTest() {
		CertificateValidator cv = CertificateValidator
				.fromCertificate(DSSUtils.loadCertificate(new File("src/test/resources/certificates/john_doe_tc.crt")));
		cv.setCertificateVerifier(new CommonCertificateVerifier());
		CertificateReports reports = cv.validate();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		assertEquals(3, usedCertificates.size());

		CertificateWrapper certificateWrapper = usedCertificates.get(0);
		assertTrue(certificateWrapper.isQcCompliance());
		assertFalse(certificateWrapper.isSupportedByQSCD());
		assertEquals(1, certificateWrapper.getQCTypes().size());
		assertEquals(QCType.QCT_ESIGN, certificateWrapper.getQCTypes().iterator().next());
		assertEquals(1, certificateWrapper.getQcLegislationCountryCodes().size());
		assertEquals("TC", certificateWrapper.getQcLegislationCountryCodes().iterator().next());
	}

	@Test
	public void userFriendlyIdentifierProviderTest() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer"));
		CertificateValidator cv = CertificateValidator.fromCertificate(certificate);
		cv.setCertificateVerifier(new CommonCertificateVerifier());
		cv.setTokenIdentifierProvider(new UserFriendlyIdentifierProvider());

		CertificateReports reports = cv.validate();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SimpleCertificateReport simpleReport = reports.getSimpleReport();

		assertEquals(3, diagnosticData.getUsedCertificates().size());
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			assertTrue(certificateWrapper.getId().contains("CERTIFICATE"));
			assertTrue(certificateWrapper.getId().contains(
					DSSUtils.replaceAllNonAlphanumericCharacters(certificateWrapper.getCommonName(), "-")));
			assertTrue(certificateWrapper.getId().contains(
					DSSUtils.formatDateWithCustomFormat(certificateWrapper.getNotBefore(), "yyyyMMdd-HHmm")));

			assertTrue(simpleReport.getCertificateIds().contains(certificateWrapper.getId()));
		}

		String certId = new UserFriendlyIdentifierProvider().getIdAsStringForToken(certificate);
		assertFalse(certId.endsWith(
				DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyyMMdd-hhmm")));
		assertTrue(certId.endsWith(
				DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyyMMdd-HHmm")));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport.getXmlCertificateById(certId));
	}
	
	@Test
	public void externalResourcesOCSPSourceTest() {
		CertificateToken certToken = DSSUtils.loadCertificateFromBase64EncodedString("MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjAwNDIyMTUzMDA4WhcNMjIwMjIyMTYzMDA4WjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKYO5OOxN//Q5bteod82QcDXssyCD6EXMuvGcmkcybrGij0eKITwg4QxiH/6I20P1Huv9Iw3IGmluhzRHMn3k4+pwVM6U7s/bIT9QZBvtLXC9ElIuS6immXPOKyjyyileeoKz8Ttv54/rtiqhZa8zX+3xXJ2mMI4f/EAbsM7XdAxsLhMq0MfpRXo3GsOgjWIaRmKkxEWz4mBtgW2B0tFZdC395rbVdlkH/hgn+oEC7ciXSqlni0vwPiI73Waa3iBv+QPNDXDVQXg/Ont7FJc1/6gaTnP57/zAz+xQMM8PF8Key9hBuXnxKV/FjC/y0Mb3fNAfkWkwPFziDJavRXfj8MCAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFNzF6OF04bgVI8auOvXQk3QOaP/LMA0GCSqGSIb3DQEBCwUAA4IBAQDLtIiIuxyUlfkUIrApCCiRYyEeA1N0eGjqG2EfIGZtDEpRxzYM7hL/K96Df3eEtP76gSWto6/2nlcUNT9wpcCWTAvMMMycrbYNyEixCyMzuxpEe/0eU3+4D7YtMYcCsASh0Wg5T2Dttx1gVQrDB8fbM02BSdH/7FTcKDh1bcnOc8McxZrDN9IHi0GXQnEphwPqBmUM+lPa6eGBO0m/4moRZAED6+V+EQL8QRTT/AKxD8RlBUCJhhYtsvhl8uD8TdYBf7uAt2k2Rp5bTbvwKPPOJEGosvjG1A/gd43isijMhcD7uF2JCEwo9P3Pb3g+U37QoRBseWp1tErSM8N3m8Xl");
		CertificateToken caToken = DSSUtils.loadCertificateFromBase64EncodedString("MIID6jCCAtKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjAwNDIyMTUzMDA2WhcNMjIwMjIyMTYzMDA2WjBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQuv1r3qUKO8M1NJ9zhXBm0X5kYzvbNlqsY5kH9cxQDc9oKLFJ+/m9TihsYt+Uw06EMahu6uejcRQFvUJNwEgHDDQ/kzo53kFfhX53GxZFgEvnQXcc4DTkANHspvUzMoEadHJBtkD/Y+pb99uXOmzMG+eC1N41MxKmnd30cc0Z8HTIWlYlW8/pq+FHO/6oVwvU7BrOKK7sMlAGzfQ0eNtaUjDPN0lnf/AXNLt3bh8I2wtTpf+zEf4TIEkUDIdTWwtKlbjkHRDfljzGGeBLcw8QN4HY72AkLE6jaNfIKQ7l5FgiRJKEdLDASxKDUEMHBam4gu+1FxebtsyAjvxLwJOBAgMBAAGjgdQwgdEwDgYDVR0PAQH/BAQDAgEGMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NybC9yb290LWNhLmNybDBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUHMAKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9yb290LWNhLmNydDAdBgNVHQ4EFgQUSva2Hgkel64xzaVSMNW9002bn78wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAWz7olSj8/yyL7ydRsjsSAiw0rXTfV5AYymFsm5cNsPDFyurKTgq8WLOSSbedRcD1vhnNNkN/V4YdU5u/hK34jcDgoHRECAZET8Qahu3Q+CPNf1KWfkTQNME+CV8g16WW+rgFhHHITt/1WRNv1TwUnQ6hNESmhzXTZ/3S88nUz8oWm2nliXj0YQ2QGTZwEZOVl9crRLNLIKEkp6/A71pncgZgMfapZdF902l1BsvoP+geUCAQX1V2m767DTfkE3yST1Cw2l9x4VyZ7Dar3HkFPhIDhhFliXD/aXcAluhR9T8ehZt29xIrnMZZXFYtJfRKfn8pu8ostb8vVsTrXWdQTA==");

		String ocspBinaries = "MIIIjQoBAKCCCIYwggiCBgkrBgEFBQcwAQEEgghzMIIIbzB8ohYEFLwDxYweQPnUd/T9BkTHDhUN5mq7GA8yMDIxMDcwMjA5MjQ1NFowUTBPMDowCQYFKw4DAhoFAAQULFsRCayq2JfWOw4G6WfL7rWAHDQEFEr2th4JHpeuMc2lUjDVvdNNm5+/AgEKgAAYDzIwMjEwNzAyMDkyNDU0WjANBgkqhkiG9w0BAQsFAAOCAQEAihhvhwCiZdIG7UI6XrBUv4yfMx/Htjzf2a1p0fZyg06eSHqXKLG3UmvwZhY/ZGRZxwKWVS0tgjZobwLLJzCFrTd+kGgRRfMIRuSSizWHjxsWWfbbihe4pTPktXJuik2+p6bL684kmca+MWoEE7BRe21QKYye2nlHyPD48/PqbOGp2h0zrxOWgw7SnHiILDxukMT1G6T44g9NFICf/BiXxztuHGUW/y+a/HhXU5gUiLTOlun8i5CRSrHUwc+Fzr+UmnJTFWnaLZSDNhYcMQkZFwvdYBHJIoKSRLxwkCh6wqrNDlXUPlDhjDIfwkIWRX4ZFjOWPLQ0qdEadyBBuf1ax6CCBtkwggbVMIIDdjCCAl6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjAwMzIyMTYzMDA2WhcNMjIwMzIyMTYzMDA2WjBUMRcwFQYDVQQDDA5vY3NwLXJlc3BvbmRlcjEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv0lVOUqvnDHo5FuF5z0K7X1Wv40z9TztmsIL327mo6u6yc536JeHyDKOKKNhHA4j3l+C6YC1U38s+G88m0wdnq0iKKcCBjyfK3Zo7uP7NN+/tl8PkGRFEOxOddeMk5K5xVhnH5DFaFelsBZ+1eMj2xLeNKL4VpyILLCAMvMeanz+Du5CezxQ3TeZkqEK8Ty5CulbEpjTMLT+P1W7tbP0xUWDSdaZuD2Gf5mFYB0vBm/Q2H835O10wEq1+bCxCwhSv6BDgr+KiHX4VuuKYvhX+/8XJluZebO2A+1EquUyTLRLqAQ8N5VMltMNmPjSOlQEHvaarpH2ieYWs56unMRL+QIDAQABo1owWDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwkwHQYDVR0OBBYEFLwDxYweQPnUd/T9BkTHDhUN5mq7MA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQELBQADggEBAEv5UvA0TwktO6j2XlJXNWY2cUJFIvYAyqSuM7ilVdK8lDlwaQOIjglknuXbihlJbOHbx9S9engD1G0jVXcPIZkJ6FV5Bdu4Q09OkVlqTOQxMTHZqelx3JdvaYuMIn+XVPM+ceWmEMEJBNmQu/OThevtsoxu5ArGN6OCd1YrsyhLtIoWKOA/6TRZ3R2UBYbebe4x/3yht6Iftaz+UKYd2gLmL4LxIX6sh+l0IZphwMTU9LExzKQ2gr4ZISPxw+iikMn1F10uhxev/MR2iouJ34w6QtujPk39NtaMMrVhGK2hYThHalp+d4I6pshDqLoVX/J+aNz/eVmdC9ZgyGO54IIwggNXMIICP6ADAgECAgEBMA0GCSqGSIb3DQEBDQUAME0xEDAOBgNVBAMMB3Jvb3QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTAeFw0yMDAzMjIxNjMwMDVaFw0yMjAzMjIxNjMwMDVaME0xEDAOBgNVBAMMB3Jvb3QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIu5CAtfNgsa14n01ZRhUu650QYlFnOX/+tWifhlwJvg7YmZXaZqMr4HUhlrH75CCIVjkGCS1GUQ/QSPU7Ls4avfMBJAkRkFAfp3/h5F9dmeyGTdbq0TdCVvd5bGp/KkJDNe7ZFKj9EfBUUT1Hq2EV573ut5T6izAI6m8QOAFSaWWqyL3GTJMLmyszWRQa3wldVMpSiIDZ04IYA5TyEGvkzsdOJBDDARhb85dyh6yxieHCIF+zvtOV7A3TvdOvZwyVPvrLRLBJn/i1WTUMmO6yurG9yiWcu1MVh8H1YPO65PWBWglpAkvjFZu852RTR44gb/caCqzW/0npbe+CUD0ckCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQzK34iOtyy36wGxfD+Zm9pASMgeTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAQBJabKGUs3Gzssex/PIiz/F1XxELJzAnGi8KanUyllmhpzqZV5LV0PcXKOGlUWyWWoK28FH2RyZG/Bs+ymF+6uUTJsPG5BblmQVsfK5x1LEs7LWZOWOozbRX8oOE0kCtOIlaAHwntZ6SUraahE3fd1XNaHSyb1st1i00nBk5WymOPPwvoY+mJTMW8h95obr1qHQ+u2MOsbyJqKxab5nW2SN56/7eVWqMYkD/yF12ftIK9EGCmGTLqF8XP4pKPm8PYoQO39/HoEKzE8F0wgWbGtJwyXknjll7DwF6bFFLXx2q+sY0ICh6ErVP2GFWpXVMkhM3NQFVhN6f954peJORP7u";

		ExternalResourcesOCSPSource ocspSource = null;
		try (InputStream baisOneOcsp = new ByteArrayInputStream(Utils.fromBase64(ocspBinaries))) {
			ocspSource = new ExternalResourcesOCSPSource(baisOneOcsp);
		} catch (IOException e) {
			fail(e);
		}
		assertNotNull(ocspSource);

		CertificateValidator cv = CertificateValidator.fromCertificate(certToken);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setOcspSource(ocspSource);
		CommonTrustedCertificateSource trustedCertSources = new CommonTrustedCertificateSource();
		trustedCertSources.addCertificate(caToken);
		certificateVerifier.setTrustedCertSources(trustedCertSources);
		cv.setCertificateVerifier(certificateVerifier);

		CertificateReports reports = cv.validate();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		CertificateWrapper endEntityCertificate = diagnosticData.getUsedCertificateById(certToken.getDSSIdAsString());
		assertNotNull(endEntityCertificate);

		CertificateWrapper caCertificate = endEntityCertificate.getSigningCertificate();
		assertNotNull(caCertificate);
		assertEquals(caToken.getDSSIdAsString(), caCertificate.getId());

		List<CertificateRevocationWrapper> certificateRevocationData = endEntityCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());

		CertificateRevocationWrapper revocationWrapper = certificateRevocationData.get(0);
		assertEquals(RevocationType.OCSP, revocationWrapper.getRevocationType());
		XmlDigestAlgoAndValue digestAlgoAndValue = revocationWrapper.getDigestAlgoAndValue();
		assertNotNull(digestAlgoAndValue);

		assertArrayEquals(DSSUtils.digest(digestAlgoAndValue.getDigestMethod(), Utils.fromBase64(ocspBinaries)),
				digestAlgoAndValue.getDigestValue());
	}

	@Test
	public void externalResourcesCRLSourceTest() {
		CertificateToken certToken = DSSUtils.loadCertificateFromBase64EncodedString("MIIEBTCCAu2gAwIBAgILBAAAAAABQeUqkm4wDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMTMxMDIzMTEwMDAwWhcNMTkwMTIzMTEwMDAwWjBjMQswCQYDVQQGEwJCRTENMAsGA1UEBRMEMjAxNDEjMCEGA1UEChMaQmVsZ2l1bSBGZWRlcmFsIEdvdmVybm1lbnQxIDAeBgNVBAMTF1RpbWUgU3RhbXBpbmcgQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuurzcUZ9xj0Hxj8pzLPSdodxbl9hTzmvVFjVwkPlO/CKItuMv5jdX78vkJyxDoCIzlaydC8iX6LKVvbKWS8DHU4Q9vUg9jlyPrG3pM8/7uMKEiVJlo1Q7G/j3ycVIfKW5JgLEUkkA7prtjxumaUaNtoSoLXVbHU+4qIVLuBOq7dYwZN0oftYM6cUEslqDi8OSAZVyPYvUNI7klcQRh28duuMyUXhOzu4neBz49uSA5c3nAIHJxJH+zsIEIZ/rv2+oiFsN3NRy8mu8sHwOR1bf81SP73C6Gsgx0cjb4JaEvAdEXayOx5YjIkp8p9rF0sMHbimYy6Xhg6uAzObjFrQtwIDAQABo4H0MIHxMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBDBgNVHSAEPDA6MDgGBmA4CQEBBTAuMCwGCCsGAQUFBwIBFiBodHRwOi8vcmVwb3NpdG9yeS5wa2kuYmVsZ2l1bS5iZTAdBgNVHQ4EFgQUhy+xl8l/bUtfYofrFHxPI0hLRJIwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5wa2kuYmVsZ2l1bS5iZS9iZWxnaXVtMi5jcmwwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBSFiuv0xbu+DlkDlN7WgAEV4xCcOTANBgkqhkiG9w0BAQUFAAOCAQEAKtng/BMJwJ4moDPdh0wJbMcDupg7Cr3PboLqNiVtJHtojtgya5+LDfIpDaBt054es/OKV3fNd40LU1eNBj0flU0SNgxwRqqWwBjdpBj9XCZsLsTlCjLDG7HJq6toyAfXYjHBj3KldUQS2g4wf3nxeQgDbLTs28MhpJWN9FCk2DJ63aPEbAZ/HA20NPAb86KM/LhO2AlkDwhpP510ih1dBWjiwNRrkrmxInW+PCQmBGR60rqRs5f8naosyR8URDz/wHiQ4Arn/HrX/KVZ2HMD8pt1IZY+5LuIuA2fn0hNCQyrGZoa3HNqIIP5zfavw0Tp+jDKLNNSsi5L8CP128lkug==");
		CertificateToken caToken = DSSUtils.loadCertificateFromBase64EncodedString("MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=");

		String crlBinaries = "MIIBbTBXMA0GCSqGSIb3DQEBBQUAMCgxCzAJBgNVBAYTAkJFMRkwFwYDVQQDExBCZWxnaXVtIFJvb3QgQ0EyFw0xNDA3MDExMTAwMDBaFw0xNTAxMzExMTAwMDBaMA0GCSqGSIb3DQEBBQUAA4IBAQClCqf+EHb/ZafCIrRXdEmIOrHV0fFYfIbLEWUhMLIDBdNgcDeKjUOB6dc3WnxfyuE4RzndBbZA1dlDv7wEX8sxaGzAdER166uDS/CF7wwVz8voDq+ju5xopN01Vy7FNcCA43IpnZal9HPIQfb2EyrfNu5hQal7WiKE7q8PSch1vBlB9h8NbyIfnyPiHZ7A0B6MPJBqSCFwgGm+YZB/4DQssOVui0+kBT19uUBjTG0QEe7dLxZTBEgBowq5axv93QBXe0j+xOXZ97tlU2iJ51bsLY3E134ziMV6hKPsBw6ARMq/BF64P6axLIUOqdCRaYoMu2ekfYSoFuaM3l2o79aw";

		ExternalResourcesCRLSource crlSource = null;
		try (InputStream baisOneCrl = new ByteArrayInputStream(Utils.fromBase64(crlBinaries))) {
			crlSource = new ExternalResourcesCRLSource(baisOneCrl);
		} catch (IOException e) {
			fail(e);
		}
		assertNotNull(crlSource);

		CertificateValidator cv = CertificateValidator.fromCertificate(certToken);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setCrlSource(crlSource);
		CommonTrustedCertificateSource trustedCertSources = new CommonTrustedCertificateSource();
		trustedCertSources.addCertificate(caToken);
		certificateVerifier.setTrustedCertSources(trustedCertSources);
		cv.setCertificateVerifier(certificateVerifier);

		CertificateReports reports = cv.validate();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		CertificateWrapper endEntityCertificate = diagnosticData.getUsedCertificateById(certToken.getDSSIdAsString());
		assertNotNull(endEntityCertificate);

		CertificateWrapper caCertificate = endEntityCertificate.getSigningCertificate();
		assertNotNull(caCertificate);
		assertEquals(caToken.getDSSIdAsString(), caCertificate.getId());

		List<CertificateRevocationWrapper> certificateRevocationData = endEntityCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());

		CertificateRevocationWrapper revocationWrapper = certificateRevocationData.get(0);
		assertEquals(RevocationType.CRL, revocationWrapper.getRevocationType());
		XmlDigestAlgoAndValue digestAlgoAndValue = revocationWrapper.getDigestAlgoAndValue();
		assertNotNull(digestAlgoAndValue);

		assertArrayEquals(DSSUtils.digest(digestAlgoAndValue.getDigestMethod(), Utils.fromBase64(crlBinaries)),
				digestAlgoAndValue.getDigestValue());
	}

	@Test
	public void shortTermCertificateTest() {
		CertificateToken shortTermCertificate = DSSUtils.loadCertificateFromBase64EncodedString("MIIDJjCCAg6gAwIBAgIIMMSTGSdLPxQwDQYJKoZIhvcNAQENBQAwKDEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczELMAkGA1UEBhMCTFUwHhcNMjEwNzAxMTAwMTI5WhcNMjEwNzAxMTAwNjI5WjA2MQwwCgYDVQQDDANBIGExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsW0yfJBqh9CtbfOtsZcEAEvzzfPusdhZNv0JSq8frKGMqJwTgjnkMJd9D3sEHUBJP0ryAmK9L5S+lWOGDhdYcE8K00k3hZSHyrOdRblB0SZhtXIgeGD7ESdTU9xPCf4Ze7xSI08zlk9NmTaj5Xqfyako8sxHAQapdXw8kfG0Ol6UhfMg7MjN8/wZrIVUYZzBQP3RFKHFQIms+pxfWxvETsynn/n2rOjuAsV0aTWGUAeWJRFJxKLSTrHQiQULVS1MHIIkdbQZxMA+Jn3dXwVdJLX/JRSvEOBqGRrvGQtYN2vNdrJlNHP0WGcSAddweWs7Ar+Pp7Qm/HEQF5+EOPUQDQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCBsAwIwYIKwYBBQUHAQMEFzAVMBMGBgQAjkYBBjAJBgcEAI5GAQYBMA0GBwQAi+xJAgEEAgUAMA0GCSqGSIb3DQEBDQUAA4IBAQBAYj8mdKsj/mMoM4HXL/w+xeK0iM55eGyBNprwxECoCH8ZCgVrVTb3eKttTXYrXjk3Yqpg3amkm7aV94iXJ0qLER/2C9lHLv6h1CoxYCdevAUSVOIzF0SJj54dxrwDQ7uTFXRe2etOg+hmEhj3OBpd/5vMfdIViYHtpPoCyZoQyGLztUt1k8/JvBe91UGAEnWx0nvokehkTgueq7dsTjBit4dlCmfmIzQUUWCgNpe1S1nEb0B/BCXaqPRhYx1//2T/5gR1lKe36HHp5rUURKT8NsS76lfxdor9Ag3mVmsw1NcVtDiFo0molO84+B53yqRP2wCU7MtfKfCX9CocgVNF");
		CertificateValidator cv = CertificateValidator.fromCertificate(shortTermCertificate);
		cv.setCertificateVerifier(new CommonCertificateVerifier());

		CertificateReports reports = cv.validate();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		assertEquals(1, usedCertificates.size());

		CertificateWrapper certificateWrapper = usedCertificates.get(0);
		assertTrue(certificateWrapper.isValAssuredShortTermCertificate());
	}

}
