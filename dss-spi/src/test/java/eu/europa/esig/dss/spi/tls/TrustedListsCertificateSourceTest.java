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
package eu.europa.esig.dss.spi.tls;

import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustedListsCertificateSourceTest {

	private static final CertificateToken CERT;

	static {
		CERT = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=");
	}

	@Test
	void testWithTrustServiceException() {
		TrustedListsCertificateSource trustedCertSource = new TrustedListsCertificateSource();
		Exception exception = assertThrows(UnsupportedOperationException.class,
				() -> trustedCertSource.addCertificate(CERT));
		assertEquals("Cannot directly add certificate to a TrustedListsCertificateSource", exception.getMessage());
	}

	@Test
	void trustPropertiesNullTest() {
		TrustedListsCertificateSource trustedCertSource = new TrustedListsCertificateSource();
		assertFalse(trustedCertSource.isTrusted(CERT));

		Exception exception = assertThrows(NullPointerException.class, () -> trustedCertSource.setTrustPropertiesByCertificates(null));
		assertEquals("TrustPropertiesByCerts cannot be null!", exception.getMessage());

		trustedCertSource.setTrustPropertiesByCertificates(new HashMap<>());

		Map<CertificateToken, List<TrustProperties>> trustPropertiesMap = new HashMap<>();
		trustPropertiesMap.put(null, null);

		exception = assertThrows(NullPointerException.class, () -> trustedCertSource.setTrustPropertiesByCertificates(trustPropertiesMap));
		assertEquals("The certificate must be filled", exception.getMessage());

		trustPropertiesMap.clear();
		trustPropertiesMap.put(CERT, null);

		exception = assertThrows(NullPointerException.class, () -> trustedCertSource.setTrustPropertiesByCertificates(trustPropertiesMap));
		assertEquals("TrustPropertiesList must be filled", exception.getMessage());

		trustPropertiesMap.clear();
		trustPropertiesMap.put(CERT, new ArrayList<>());
		trustedCertSource.setTrustPropertiesByCertificates(trustPropertiesMap);

		assertTrue(trustedCertSource.isTrusted(CERT));
	}

	@Test
	void trustTimeNullTest() {
		TrustedListsCertificateSource trustedCertSource = new TrustedListsCertificateSource();
		assertFalse(trustedCertSource.isTrusted(CERT));

		Exception exception = assertThrows(NullPointerException.class, () -> trustedCertSource.setTrustTimeByCertificates(null));
		assertEquals("trustTimeByCertificate cannot be null!", exception.getMessage());

		trustedCertSource.setTrustTimeByCertificates(new HashMap<>());

		Map<CertificateToken, List<CertificateTrustTime>> certTrustTimeMap = new HashMap<>();
		certTrustTimeMap.put(null, null);

		exception = assertThrows(NullPointerException.class, () -> trustedCertSource.setTrustTimeByCertificates(certTrustTimeMap));
		assertEquals("The certificate must be filled", exception.getMessage());

		certTrustTimeMap.clear();
		certTrustTimeMap.put(CERT, null);

		exception = assertThrows(NullPointerException.class, () -> trustedCertSource.setTrustTimeByCertificates(certTrustTimeMap));
		assertEquals("CertificateTrustTimes must be filled", exception.getMessage());

		certTrustTimeMap.clear();
		certTrustTimeMap.put(CERT, new ArrayList<>());
		trustedCertSource.setTrustTimeByCertificates(certTrustTimeMap);

		assertTrue(trustedCertSource.isTrusted(CERT));
	}

	@Test
	void trustTimeEmptyTest() {
		TrustedListsCertificateSource trustedCertSource = new TrustedListsCertificateSource();

		assertFalse(trustedCertSource.isTrusted(CERT));
		assertFalse(trustedCertSource.isTrustedAtTime(CERT, new Date()));

		CertificateTrustTime trustTime = trustedCertSource.getTrustTime(CERT);
		assertNotNull(trustTime);
		assertFalse(trustTime.isTrusted());
		assertFalse(trustTime.isTrustedAtTime(new Date()));

		Map<CertificateToken, List<CertificateTrustTime>> certTrustTimeMap = new HashMap<>();

		List<CertificateTrustTime> certificateTrustTimeList = new ArrayList<>();
		certTrustTimeMap.put(CERT, certificateTrustTimeList);

		trustedCertSource.setTrustTimeByCertificates(certTrustTimeMap);

		assertTrue(trustedCertSource.isTrusted(CERT));
		assertTrue(trustedCertSource.isTrustedAtTime(CERT, new Date()));

		trustTime = trustedCertSource.getTrustTime(CERT);
		assertNotNull(trustTime);
		assertTrue(trustTime.isTrusted());
		assertTrue(trustTime.isTrustedAtTime(new Date()));
		assertNull(trustTime.getStartDate());
		assertNull(trustTime.getEndDate());
	}

	@Test
	void trustTimeWithValuesTest() {
		TrustedListsCertificateSource trustedCertSource = new TrustedListsCertificateSource();

		Map<CertificateToken, List<CertificateTrustTime>> certTrustTimeMap = new HashMap<>();

		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.YEAR, -1);
		Date startDate = calendar.getTime();

		calendar.add(Calendar.YEAR, 2);
		Date sunsetDate = calendar.getTime();

		List<CertificateTrustTime> certificateTrustTimeList = new ArrayList<>();
		certificateTrustTimeList.add(new CertificateTrustTime(startDate, sunsetDate));
		certTrustTimeMap.put(CERT, certificateTrustTimeList);

		trustedCertSource.setTrustTimeByCertificates(certTrustTimeMap);

		assertTrue(trustedCertSource.isTrusted(CERT));
		assertTrue(trustedCertSource.isTrustedAtTime(CERT, new Date()));

		CertificateTrustTime trustTime = trustedCertSource.getTrustTime(CERT);
		assertNotNull(trustTime);
		assertTrue(trustTime.isTrusted());
		assertTrue(trustTime.isTrustedAtTime(new Date()));
		assertEquals(startDate, trustTime.getStartDate());
		assertEquals(sunsetDate, trustTime.getEndDate());

		calendar.setTime(new Date());
		calendar.add(Calendar.YEAR, -2);
		Date extendedStartDate = calendar.getTime();

		calendar.add(Calendar.YEAR, 4);
		Date extendedSunsetDate = calendar.getTime();

		certificateTrustTimeList.clear();
		certificateTrustTimeList.add(new CertificateTrustTime(startDate, sunsetDate));
		certificateTrustTimeList.add(new CertificateTrustTime(extendedStartDate, extendedSunsetDate));
		trustedCertSource.setTrustTimeByCertificates(certTrustTimeMap);

		assertTrue(trustedCertSource.isTrusted(CERT));
		assertTrue(trustedCertSource.isTrustedAtTime(CERT, new Date()));

		trustTime = trustedCertSource.getTrustTime(CERT);
		assertNotNull(trustTime);
		assertTrue(trustTime.isTrusted());
		assertTrue(trustTime.isTrustedAtTime(new Date()));
		assertEquals(extendedStartDate, trustTime.getStartDate());
		assertEquals(extendedSunsetDate, trustTime.getEndDate());

		calendar.add(Calendar.YEAR, 1);
		Date futureTime = calendar.getTime();
		assertFalse(trustedCertSource.isTrustedAtTime(CERT, futureTime));
		assertFalse(trustTime.isTrustedAtTime(futureTime));
	}

}
