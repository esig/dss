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
package eu.europa.esig.dss.tsl.dto.condition;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;

class KeyUsageConditionTest {

	@Test
	void test() {
		CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID3DCCAsSgAwIBAgIER/idhzANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJFRTEiMCAGA1UEChMZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEPMA0GA1UECxMGRVNURUlEMRcwFQYDVQQDEw5FU1RFSUQtU0sgMjAwNzAeFw0wODA0MDYwOTUzMDlaFw0xMjAzMDUyMjAwMDBaMIGWMQswCQYDVQQGEwJFRTEPMA0GA1UEChMGRVNURUlEMRowGAYDVQQLExFkaWdpdGFsIHNpZ25hdHVyZTEiMCAGA1UEAxMZU0lOSVZFRSxWRUlLTywzNjcwNjAyMDIxMDEQMA4GA1UEBBMHU0lOSVZFRTEOMAwGA1UEKhMFVkVJS08xFDASBgNVBAUTCzM2NzA2MDIwMjEwMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGRN42R9e6VEHMCyvacuubjtm1+5Kk92WgIgtWA8hY8DW2iNvQJ3jOF5XlVIyIDTwl2JVKxWKhXX+8+yNFPpqAK43IINcmMfznw/KcR7jACGNuTrivA9HrvRiqDzTg5E1rktjho6OkDkdV3dgOLB2wyhVm2anNpICfrUq8c09HPwIDMMP5o4HvMIHsMA4GA1UdDwEB/wQEAwIGQDA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vd3d3LnNrLmVlL2NybHMvZXN0ZWlkL2VzdGVpZDIwMDcuY3JsMFEGA1UdIARKMEgwRgYLKwYBBAHOHwEBAQEwNzASBggrBgEFBQcCAjAGGgRub25lMCEGCCsGAQUFBwIBFhVodHRwOi8vd3d3LnNrLmVlL2Nwcy8wHwYDVR0jBBgwFoAUSAbevoyHV5WAeGP6nCMrK6A6GHUwHQYDVR0OBBYEFJAJUyDrH3rdxTStU+LDa6aHdE8dMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEFBQADggEBAA5qjfeuTdOoEtatiA9hpjDHzyqN1PROcaPrABXGqpLxcHbLVr7xmovILAjxS9fJAw28u9ZE3asRNa9xgQNTeX23mMlojJAYVbYCeIeJ6jtsRiCo34wgvO3CtVfO3+C1T8Du5XLCHa6SoT8SpCApW+Crwe+6eCZDmv2NKTjhn1wCCNO2e8HuSt+pTUNBTUB+rkvF4KO9VnuzRzT7zN7AUdW4OFF3bI+9+VmW3t9vq1zDOxNTdBkCM3zm5TRa8ZtyAPL48bW19JAcYzQLjPGORwoIRNSXdVTqX+cDiw2wbmb2IhPdxRqN9uPwU1x/ltZZ3W5GzJ1t8JeQN7PuGM0OHqE=");

		KeyUsageCondition c = new KeyUsageCondition(KeyUsageBit.DIGITAL_SIGNATURE, true);
		assertFalse(c.check(certificate));

		KeyUsageCondition c2 = new KeyUsageCondition(KeyUsageBit.NON_REPUDIATION, true);
		assertTrue(c2.check(certificate));
	}

}
