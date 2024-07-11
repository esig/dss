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
package eu.europa.esig.dss.xades;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;

import org.bouncycastle.asn1.x509.IssuerSerial;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

class IssuerV2Test {

	@Test
	void test() throws IOException {
		String certB64 = "MIIFeDCCBGCgAwIBAgIHAJAJnM9KvzANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJGUjENMAsGA1UEChMERVRTSTEcMBoGA1UECwwTUGx1Z3Rlc3RzXzIwMTUtMjAxNjETMBEGA1UEAxMKTGV2ZWxCQ0FPSzAeFw0xNjExMDkxNDQzNTNaFw0xNzAyMDkxNDQzNTNaMGExCzAJBgNVBAYTAkhVMRQwEgYDVQQKEwtkZXZlbG9wbWVudDERMA8GA1UEBBMIQ3pla21hbnkxDzANBgNVBCoTBkJhbGF6czEYMBYGA1UEAxMPQmFsYXpzIEN6ZWttYW55MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAje9XQHZkVc+7Z6wvi9qWB6Dsfg9/9tRzbzwVEIIBQ0y7l6FWPQUjrIjrSPX1CvSNAufimJRCdsOkZoqZTxax+iRE8eVUOWjXZgfhhZzO10BBZsFY2o1sMwMR3QeYTvMuK5ltnNSlp0fegntNLU/vub4vI+YMfaFc0CfbRuhxnF/3+unOuBe2hLskn9IzlKrLVJg4R2oC7oH7nqYnnI5SemJKpNL/SniyNgewSSeY5/g7qZ2k+Ua3f51IiWnKMAQhzSIQSB1L+HsPtzv2NzYDmmqFmWGvEonQlpfz87EfgP16vP6wT3HIxe5r2Ufn7YwOIYpwTTEWnyWdGMaG3ImdMwIDAQABo4ICRTCCAkEwDgYDVR0PAQH/BAQDAgeAMIIBCgYIKwYBBQUHAQEEgf0wgfowRwYIKwYBBQUHMAKGO2h0dHA6Ly9lc2lnLXBvcnRhbC5ldHNpLm9yZy9jYXBzby9jZXJ0cy9TQ09LL0xldmVsQkNBT0suY2VyMG0GCCsGAQUFBzAChmFsZGFwOi8vZXNpZy1wb3J0YWwuZXRzaS5vcmcvQ049TGV2ZWxCQ0FPSyxPVT1QbHVndGVzdHNfMjAxNi0yMDE3LE89RVRTSSxDPUZSP2NBQ2VydGlmaWNhdGU7YmluYXJ5MEAGCCsGAQUFBzABhjRodHRwOi8vZXNpZy1wb3J0YWwuZXRzaS5vcmcvY2Fwc28vb2NzcD9jYT1MZXZlbEJDQU9LMB8GA1UdIwQYMBaAFChS6qb2PY61Xi7tip03rqP7Xg0QMIG/BgNVHR8EgbcwgbQwgbGgga6ggauGbWxkYXA6Ly9lc2lnLXBvcnRhbC5ldHNpLm9yZy9DTj1MZXZlbEJDQU9LLE9VPVBsdWd0ZXN0c18yMDE2LTIwMTcsTz1FVFNJLEM9RlI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdDtiaW5hcnmGOmh0dHA6Ly9lc2lnLXBvcnRhbC5ldHNpLm9yZy9jYXBzby9jcmxzL1NDT0stTGV2ZWxCQ0FPSy5jcmwwHwYDVR0RBBgwFoEUY3pla21hbnlAbWljcm9zZWMuaHUwHQYDVR0OBBYEFMqOCLybW2+yshHgmaNDY0DuyK0eMA0GCSqGSIb3DQEBCwUAA4IBAQA0VsA19UiNIXTWOi5kZS9OeNNWen59UVaM4YpUzVbuViASA+S6dGvJO0hXFeZouou4VHUaHq/l8h8TR/1nsJCnMbaTa8tPt46ThNtGmn0lVm0AavU4NzDPo5t0LLgkGL78mFYUmY3ZHOOehSkLfU5GdLrRKziCXbTaPK0TxTj+eQuVOarIo9wo+cjmGOs42pfSlfpSSOxQ+iO3mdbVhCJWK+demryqnZRkmI+BsQdMi/i9+92kWaripzYUaOTzHqRwtrHvefDQNjDkA/oAZ78d/zMG88hnXfMAiVGg4ZfNjW1sic8ffKxHpSskjBTr7VBin32/Lqc+XIUFM1hB+jBO";
		CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(certB64);
		assertNotNull(certificate);

		IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(certificate);
		String b64 = Utils.toBase64(DSSASN1Utils.getDEREncoded(issuerSerial));

		assertEquals("MF4wU6RRME8xCzAJBgNVBAYTAkZSMQ0wCwYDVQQKEwRFVFNJMRwwGgYDVQQLDBNQbHVndGVzdHNfMjAxNS0yMDE2MRMwEQYDVQQDEwpMZXZlbEJDQU9LAgcAkAmcz0q/", b64);
	}
}
