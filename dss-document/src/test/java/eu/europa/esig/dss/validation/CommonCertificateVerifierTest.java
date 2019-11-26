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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

public class CommonCertificateVerifierTest {

	@Test
	public void testEmpty() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		assertNotNull(ccv.createValidationPool());
	}

	@Test
	public void testEmptyCertSources() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		ccv.setAdjunctCertSource(new CommonCertificateSource());
		ccv.setTrustedCertSource(new CommonTrustedCertificateSource());
		assertNotNull(ccv.createValidationPool());
	}
	
	@Test
	public void testMultipleCertSources() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		ccv.setTrustedCertSource(new TrustedListsCertificateSource());
		ccv.setTrustedCertSource(new CommonTrustedCertificateSource());
		assertNotNull(ccv.createValidationPool());
		
		ccv = new CommonCertificateVerifier();
		ccv.setTrustedCertSources(new CommonTrustedCertificateSource(), new TrustedListsCertificateSource());
		assertNotNull(ccv.createValidationPool());
	}
	
	@Test
	public void testNotTrustedCertificateSource() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		Exception exception = assertThrows(DSSException.class, () -> {
			ccv.setTrustedCertSource(new CommonCertificateSource());
		});
		assertEquals("The certificateSource with type [OTHER] is not allowed in the trustedCertSources. Please, "
				+ "use CertificateSource with a type TRUSTED_STORE or TRUSTED_LIST.", exception.getMessage());
		
		exception = assertThrows(DSSException.class, () -> {
			ccv.setTrustedCertSources(new CommonTrustedCertificateSource(), new CommonCertificateSource());
		});
		assertEquals("The certificateSource with type [OTHER] is not allowed in the trustedCertSources. Please, "
				+ "use CertificateSource with a type TRUSTED_STORE or TRUSTED_LIST.", exception.getMessage());
	}
	
	@Test
	public void testReflection() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		ccv.setTrustedCertSource(new CommonTrustedCertificateSource());
		assertThrows(UnsupportedOperationException.class, () -> {
			ccv.getTrustedCertSources().add(new CommonCertificateSource());
		});
		
		assertThrows(UnsupportedOperationException.class, () -> {
			ccv.getTrustedCertSources().clear();
		});
	}
	
	@Test
	public void testClearTrustedCertSources() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		ccv.setTrustedCertSource(new CommonTrustedCertificateSource());
		assertEquals(1, ccv.getTrustedCertSources().size());
		
		ccv.clearTrustedCertSources();
		assertEquals(0, ccv.getTrustedCertSources().size());
		
		ccv.setTrustedCertSources(new CommonTrustedCertificateSource(), new TrustedListsCertificateSource());
		assertEquals(2, ccv.getTrustedCertSources().size());
	}

	@Test
	public void testNonEmptyCertSource() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		CommonCertificateSource adjunctCertSource = new CommonCertificateSource();
		CertificateToken c1 = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=");
		adjunctCertSource.addCertificate(c1);
		adjunctCertSource.addCertificate(c1);
		ccv.setAdjunctCertSource(adjunctCertSource);

		CertificatePool certificatePool = ccv.createValidationPool();
		assertNotNull(certificatePool);
		assertEquals(1, certificatePool.getNumberOfEntities());
		assertEquals(1, certificatePool.getNumberOfCertificates());
	}

	@Test
	public void testNonEmptyCertSources() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		CertificateToken c1 = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=");

		CommonCertificateSource adjunctCertSource = new CommonCertificateSource();
		adjunctCertSource.addCertificate(c1);
		ccv.setAdjunctCertSource(adjunctCertSource);

		CommonCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		trustedCertSource.addCertificate(c1);
		ccv.setTrustedCertSource(trustedCertSource);

		CertificatePool certificatePool = ccv.createValidationPool();
		assertNotNull(certificatePool);
		assertEquals(1, certificatePool.getNumberOfEntities());
		assertEquals(1, certificatePool.getNumberOfCertificates());
	}


}

