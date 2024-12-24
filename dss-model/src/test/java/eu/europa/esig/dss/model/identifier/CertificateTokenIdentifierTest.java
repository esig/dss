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
package eu.europa.esig.dss.model.identifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;

class CertificateTokenIdentifierTest {

	@Test
	void testEncapsulatedCertificateTokenIdentifier() {
		String cert = "MIID/TCCAuWgAwIBAgILBAAAAAABFWqxqn4wDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0wNzEwMDQxMjAwMDBaFw0xNDAxMjYyMzAwMDBaMCgxCzAJBgNVBAYTAkJFMRkwFwYDVQQDExBCZWxnaXVtIFJvb3QgQ0EyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnNCHpL/dQ+Lv3SGpz/tshgtLZf5qfuYSiPf1Y3gjMYyHBYtB0LWLbZuL6f1/MaFgl2V3rUiAMyoU0Cfrwo1onrH4cr3YBBnDqdQcxdTlZ8inwxdb7ZBvIzr2h1GvaeUv/May9T7jQ4eM8iW1+yMU96THjQeilBxJli0XcKIidpg0okhP97XARg2buEscAMEZe+YBitdHmLcVWv+ZmQhX/gv4debKa9vzZ+qDEbRiMWdopWfrD8VrvJh3+/Da5oi2Cxx/Vgd7ACkOCCVWsfVN2O6T5uq/lZGLmPZCyPVivq1I/CJG6EUDSbaQfA4jzDtBSZ5wUtOobh+VVI6aUaEdQIDAQABo4H4MIH1MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTBDBgNVHSAEPDA6MDgGBWA4CQEBMC8wLQYIKwYBBQUHAgEWIWh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlIDA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24ubmV0L2NybC9yb290LmNybDARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZIhvcNAQEFBQADggEBAH1t5NWhYEwrNe6NfOyI0orfIiEoy13BB5w214IoqfGSTivFMZBI2FQeBOquBXkoB253FXQq+mmZMlIl5qn0qprUQKQlicA2cSm0UgBe7SlIQkkxFusl1AgVdjk6oeNkHqxZs+J1SLy0NofzDA+F8BWy4AVSPujQ6x1GK70FdGmea/h9anxodOyPLAvWEckPFxavtvTuxwAjBTfdGB6Z6DvQBq0LtljcrLyojA9uwVDSvcwOTZK5lcTV54aE6KZWX2DapbDi2KY/oL6HfhOiDh+OPqa3YXzvCesY/h5v0RerHFFk49+ItSJryzwRcvYuzk1zYQL5ZykZc/PkVRV3HWE=";
		CertificateToken certificate = getCertificate(cert);
		TokenIdentifier tokenIdentifier = new CertificateTokenIdentifier(certificate);
		assertArrayEquals(Base64.getDecoder().decode(cert), tokenIdentifier.getBinaries());
		byte[] digestValue = tokenIdentifier.getDigestValue(DigestAlgorithm.SHA256);
		assertArrayEquals(digestValue, tokenIdentifier.getDigestValue(DigestAlgorithm.SHA256));
		assertTrue(tokenIdentifier.asXmlId().startsWith("C-"));
	}

	private CertificateToken getCertificate(String base64) {
		return getCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64)));
	}

	private CertificateToken getCertificate(InputStream isOrigin) {
		try (InputStream is = isOrigin) {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			return new CertificateToken((X509Certificate) factory.generateCertificate(is));
		} catch (Exception e) {
			throw new DSSException("Unable to read certificate", e);
		}
	}

	@Test
	void testWithNullValue() {
		assertThrows(NullPointerException.class, () -> new CertificateTokenIdentifier(null));
	}

}
