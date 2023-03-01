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
package eu.europa.esig.dss.model.x509;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.DSSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateTokenTest {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateTokenTest.class);

	@Test
	public void test() throws Exception {
		String c1 = "MIID/TCCAuWgAwIBAgILBAAAAAABFWqxqn4wDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0wNzEwMDQxMjAwMDBaFw0xNDAxMjYyMzAwMDBaMCgxCzAJBgNVBAYTAkJFMRkwFwYDVQQDExBCZWxnaXVtIFJvb3QgQ0EyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnNCHpL/dQ+Lv3SGpz/tshgtLZf5qfuYSiPf1Y3gjMYyHBYtB0LWLbZuL6f1/MaFgl2V3rUiAMyoU0Cfrwo1onrH4cr3YBBnDqdQcxdTlZ8inwxdb7ZBvIzr2h1GvaeUv/May9T7jQ4eM8iW1+yMU96THjQeilBxJli0XcKIidpg0okhP97XARg2buEscAMEZe+YBitdHmLcVWv+ZmQhX/gv4debKa9vzZ+qDEbRiMWdopWfrD8VrvJh3+/Da5oi2Cxx/Vgd7ACkOCCVWsfVN2O6T5uq/lZGLmPZCyPVivq1I/CJG6EUDSbaQfA4jzDtBSZ5wUtOobh+VVI6aUaEdQIDAQABo4H4MIH1MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTBDBgNVHSAEPDA6MDgGBWA4CQEBMC8wLQYIKwYBBQUHAgEWIWh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlIDA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24ubmV0L2NybC9yb290LmNybDARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZIhvcNAQEFBQADggEBAH1t5NWhYEwrNe6NfOyI0orfIiEoy13BB5w214IoqfGSTivFMZBI2FQeBOquBXkoB253FXQq+mmZMlIl5qn0qprUQKQlicA2cSm0UgBe7SlIQkkxFusl1AgVdjk6oeNkHqxZs+J1SLy0NofzDA+F8BWy4AVSPujQ6x1GK70FdGmea/h9anxodOyPLAvWEckPFxavtvTuxwAjBTfdGB6Z6DvQBq0LtljcrLyojA9uwVDSvcwOTZK5lcTV54aE6KZWX2DapbDi2KY/oL6HfhOiDh+OPqa3YXzvCesY/h5v0RerHFFk49+ItSJryzwRcvYuzk1zYQL5ZykZc/PkVRV3HWE=";
		String c2 = "MIID7jCCAtagAwIBAgILBAAAAAABQaHhNLowDQYJKoZIhvcNAQEFBQAwOzEYMBYGA1UEChMPQ3liZXJ0cnVzdCwgSW5jMR8wHQYDVQQDExZDeWJlcnRydXN0IEdsb2JhbCBSb290MB4XDTEzMTAxMDExMDAwMFoXDTI1MDUxMjIyNTkwMFowKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGc0Iekv91D4u/dIanP+2yGC0tl/mp+5hKI9/VjeCMxjIcFi0HQtYttm4vp/X8xoWCXZXetSIAzKhTQJ+vCjWiesfhyvdgEGcOp1BzF1OVnyKfDF1vtkG8jOvaHUa9p5S/8xrL1PuNDh4zyJbX7IxT3pMeNB6KUHEmWLRdwoiJ2mDSiSE/3tcBGDZu4SxwAwRl75gGK10eYtxVa/5mZCFf+C/h15spr2/Nn6oMRtGIxZ2ilZ+sPxWu8mHf78NrmiLYLHH9WB3sAKQ4IJVax9U3Y7pPm6r+VkYuY9kLI9WK+rUj8IkboRQNJtpB8DiPMO0FJnnBS06huH5VUjppRoR1AgMBAAGjggEEMIIBADAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATBQBgNVHSAESTBHMEUGCisGAQQBsT4BZAEwNzA1BggrBgEFBQcCARYpaHR0cDovL2N5YmVydHJ1c3Qub21uaXJvb3QuY29tL3JlcG9zaXRvcnkwHQYDVR0OBBYEFIWK6/TFu74OWQOU3taAARXjEJw5MDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9jcmwub21uaXJvb3QuY29tL2N0Z2xvYmFsLmNybDARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUtgh7DXrMrCBMhlYyXs+rboUtcFcwDQYJKoZIhvcNAQEFBQADggEBALLLOUcpFHXrT8gK9htqXI8dV3LlSAooOqLkn+yRRxt/zS9Y0X0opocf56Kjdu+c2dgw6Ph3xE/ytMT5cu/60jT17BTk2MFkQhoAJbM/KIGmvu4ISDGdeobiBtSeiyzRb9JR6JSuuM3LvQp1n0fhsA5HlibT5rFrKi7Oi1luDbc4eAp09nPhAdcgUkRU9o/aAJLAJho3Zu9uSbw5yHW3PRGnmfSO67mwsnSDVswudPrZEkCnSHq/jwOBXAWCYVu5bru3rCdojd5qCTn/WyqbZdsgLAPR5Vmf/uG3d5HxTO1LLX1Zyp9iANuG32+nFusi89shA1GPDKWacEm0ASd8iaU=";
		String c3 = "MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=";
		String c4 = "MIIFwzCCA6ugAwIBAgIUCn6m30tEntpqJIWe5rgV0xZ/u7EwDQYJKoZIhvcNAQELBQAwRjELMAkGA1UEBhMCTFUxFjAUBgNVBAoMDUx1eFRydXN0IFMuQS4xHzAdBgNVBAMMFkx1eFRydXN0IEdsb2JhbCBSb290IDIwHhcNMTUwMzA1MTMyMTU3WhcNMzUwMzA1MTMyMTU3WjBGMQswCQYDVQQGEwJMVTEWMBQGA1UECgwNTHV4VHJ1c3QgUy5BLjEfMB0GA1UEAwwWTHV4VHJ1c3QgR2xvYmFsIFJvb3QgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANeFl78RmOnwYoNMPIf5U2o3C/IPPIfOb9wmKb3FibrJgz337spbxm1Jc7TJRqMbNBM/wYlFV/TZsfs2ZUv7COJIcRHIbjuend+JZTemhfY7RBi2xjcwYkSSl2l9QjAk5A0MiWtj3sXh306pFGxT4GHO9hcvHTy95iJMHZP1EMShduxq3sVs35a0VkBCwGKSMKEtFZSg0iAGCW5qbeXrt77U8PEVfIvmTroTzEsnXpk8F12PgX8zPU/TPxvsXD/wPEx1bvKm1Z3aLQdjAsZy6ZS8TEmVT4hSyNvoaYL4zDRbIvCGp4m9SAptZoFtyMhk+wHh9OHe2Z7d21vUKpkmFRseTJIpgp7VkoGSQXAZ96Tlk0u8d2cx3Rz9MXANF5kM+Qw5GSoXtTBxVdUPrljhPS80m8+f9niFwpN6cj5mj5wWEWCPnolvZ77gR1o7DJpni89Gxq44o/KnvObWhWszJHAiS8sIm7vI+AIpHb4gDEa/a4ebsypmQjVGbKq6rfmYe+lQVRQxv7HaLe2ArWgk+2mr2HETMOZns4dA/Yl+8kPREd8vZS9kzl8UubG/Mb2HeFpZZYiq/FkySIbWTLkpS5XTdvN3JW1CHDiDTf2jX5t/Lax5Gw5CMZdjpPuKadUiDTSQMC6otOBttpSsvItO13D8xTiOZCXhTTmQzsmHhFhxAgMBAAGjgagwgaUwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGByuBKwEBAQowLDAqBggrBgEFBQcCARYeaHR0cHM6Ly9yZXBvc2l0b3J5Lmx1eHRydXN0Lmx1MA4GA1UdDwEB/wQEAwIBBjAfBgNVHSMEGDAWgBT/GCh2+UgFLKGu8SsbK7JT+Et8szAdBgNVHQ4EFgQU/xgodvlIBSyhrvErGyuyU/hLfLMwDQYJKoZIhvcNAQELBQADggIBAGoZFO1uecEsh9QNcH7X9njJCwROxLHOk3D+sFTAMs2ZMGQXvw/l4jP9BzZAcg4atmpZ1gDlaCDdLnINH2pkMSCEfUmmWjfrRcmF9dTHF5kH5ptV5AzoqbTOjFu1EVzPig4N1qx3gf4ynCSecs5U89BvolbW7MM3LGVYvlcAGvI1+ut7MV3CwRI9loGIlonBWVx65n9wNOeD4rHh4bhY79SV5GCc8JaXcozrhAIuZY+kt9J/Z93I055cqqmkoCUUBpvsT34tC38ddfEz2O3OuHVtPlu5mB0xDVbYQw8wkbIEa91WvpWAVWe+2M2D2RjuLg+GLZKecBPs3lHJQ3gCpU3I+V/EkVhGFndadKpAvAefMLmx9xIX3eP/JEAdemrRTxgKqpAd60Ae36EeRJIQmvKN4dFLRp7oRUKX6kWZ8+xm1QL68qZKJKrezrnK+T+Tb/mjuuqlPpmt/f97mfVl7vBZKGfXkJWkE4SphMHozs51k2MavDzq1WQfLSoSOcbDWjLtR5EWDrw4wVDej8oqkDQc7kGUnF4ZLvhFSZl0kbAEb+MEWrGrKqv+x9CWttrhSmQGbmBNvUJO/3jaJMobtNeWOWyu8Q6qp31IiyBMz2TWuJdGsE7RKlY6oJO9r4Ak4Ap+58rVyuiFVdw2KuGUaJPHZnJED4AhMmwlxyOAgwrr";
		
		CertificateToken certificate1 = getCertificate(c1);
		CertificateToken certificate2 = getCertificate(c2);
		CertificateToken certificate3 = getCertificate(c3);
		CertificateToken certificate4 = getCertificate(c4);
		assertNotNull(certificate1);
		assertNotNull(certificate2);
		assertNotNull(certificate3);
		assertNotNull(certificate4);

		assertNotNull(certificate1.getKeyUsageBits());
		assertNotNull(certificate1.getSignatureAlgorithm());
		assertNotNull(certificate1.getDSSId());
		assertNotNull(certificate1.getEntityKey());
		assertNotNull(certificate1.getDigest(DigestAlgorithm.SHA256));
		assertNotNull(certificate1.getDigest(DigestAlgorithm.SHA256));

		assertTrue(certificate1.checkKeyUsage(KeyUsageBit.CRL_SIGN));
		assertFalse(certificate1.checkKeyUsage(KeyUsageBit.NON_REPUDIATION));
		
		assertEquals(SignatureValidity.NOT_EVALUATED, certificate1.getSignatureValidity());
		assertEquals(SignatureValidity.NOT_EVALUATED, certificate2.getSignatureValidity());
		assertEquals(SignatureValidity.NOT_EVALUATED, certificate3.getSignatureValidity());
		assertEquals(SignatureValidity.NOT_EVALUATED, certificate4.getSignatureValidity());

		LOG.info("{}", certificate1);
		LOG.info("{}", certificate2);
		LOG.info("{}", certificate3);
		LOG.info("{}", certificate4);

		assertFalse(certificate1.isSelfIssued());
		assertTrue(certificate3.isSelfIssued());

		assertFalse(certificate1.isSignedBy(certificate3));
		assertEquals(SignatureValidity.INVALID, certificate1.getSignatureValidity());
		assertFalse(certificate1.isSelfSigned());
		assertTrue(certificate3.isSignedBy(certificate3));
		assertEquals(SignatureValidity.VALID, certificate3.getSignatureValidity());
		
		assertFalse(certificate3.isSignedBy(certificate4));
		assertEquals(SignatureValidity.INVALID, certificate3.getSignatureValidity());
		assertTrue(certificate3.isSelfSigned());
		assertEquals(SignatureValidity.VALID, certificate3.getSignatureValidity());
		assertTrue(certificate3.isSignedBy(certificate1));
		assertEquals(SignatureValidity.VALID, certificate3.getSignatureValidity());
		assertTrue(certificate3.isSignedBy(certificate2));
		assertEquals(SignatureValidity.VALID, certificate3.getSignatureValidity());

		assertFalse(certificate1.isSignatureIntact());
		assertFalse(certificate1.isValid());
		assertTrue(certificate3.isSignatureIntact());
		assertTrue(certificate3.isValid());
		
		assertNull(certificate3.getPublicKeyOfTheSigner());

		assertNotEquals(certificate1, certificate2);
		assertNotEquals(certificate1, certificate3);
		assertNotEquals(certificate1, certificate4);
		
		assertTrue(certificate1.isEquivalent(certificate1));
		assertTrue(certificate1.isEquivalent(certificate2));
		assertTrue(certificate1.isEquivalent(certificate3));
		assertFalse(certificate1.isEquivalent(certificate4));
		
		Date cert1NotBefore = certificate1.getNotBefore();
		assertTrue(certificate1.isValidOn(cert1NotBefore));
		assertFalse(certificate2.isValidOn(cert1NotBefore));
		assertTrue(certificate3.isValidOn(cert1NotBefore));
		assertFalse(certificate4.isValidOn(cert1NotBefore));
		
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(cert1NotBefore);
		calendar.add(Calendar.SECOND, -1);
		assertFalse(certificate1.isValidOn(calendar.getTime()));
		
		Date cert1NotAfter = certificate1.getNotAfter();
		assertTrue(certificate1.isValidOn(cert1NotAfter));
		assertTrue(certificate2.isValidOn(cert1NotAfter));
		assertTrue(certificate3.isValidOn(cert1NotAfter));
		assertFalse(certificate4.isValidOn(cert1NotAfter));

		calendar.setTime(cert1NotAfter);
		calendar.add(Calendar.SECOND, 1);
		assertFalse(certificate1.isValidOn(calendar.getTime()));
	}

	@Test
	public void pss() throws IOException {
		Security.addProvider(new BouncyCastleProvider());
		File certFile = new File("src/test/resources/D-TRUST_CA_3-1_2016.cer");
		try (FileInputStream fis = new FileInputStream(certFile)) {
			CertificateToken certificate = getCertificate(fis);
			assertNotNull(certificate);
			assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, certificate.getSignatureAlgorithm());
		}
	}

	@RepeatedTest(value = 100)
	public void testEquals() {
		String goodUserB64 = "MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwMzE4MDkzMTU3WhcNMjEwMTE4MDkzMTU3WjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMtKFy1gwi9R5Ai79lTIVm6Fzjze5+ir1ejBCSNTyHy1eomoTVwD+s+ZsjsdvFseKMLY9e2Cxhck3owRHqKihOhJ7JpxK3dCTCohTUHNHIqDbozLZr/zsQOst8xSEKLyKwhWyJImLcBbm017r0p8omsUojjbCmO9nFp+KE+qoWaW6WsYsXsGzICkLjRjHP1esmd5zcYzBSId9l2wr28XFGW8qBgJKXQxeUgI190MuA6AwCld5BrLXVuLvLLzXQJ27EUfnvMIBsUSu7rAxqHKrlrqeOx+vhdrPATNWX+ifGnFsJMxToQuFfF9deMO62IzrcRSi47B+BARD+kfSiuvcaECAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFLfj6J8hqF1pc5HuOqX5HORQQUQ5MA0GCSqGSIb3DQEBCwUAA4IBAQAxDzKz7YQdW/izFnRMfUgAS7cREg9F/z7lhmCT95gn7J4TGtwE1vXpPVKjGhrPPBNFfHXQ1MXMMFPwxvO1FyHUZkfVVH6+apPGyGTHoZdIlsXfJwQDxCSBCjw7Zekbc/7ljL7fPA6kbBsXdjGk6PvKSIN9YMcCuTg/fyYPoBWKGgo76V+hiQ/SVsbOzd0SHZJazg8zYFBnAS5QpB4ccGqmhrbCoL6kIMDrWTzRYCIBPpKXN5JwwxY99kDGyUVklSt91i8Q+ioI6A9C+KrwE+gbKPxyy9HmXq4lw8rod0HFG79YOpL3zbNnXFI0Hfs5+7j4EQB4Rms3fhvnKHAsYPk8";
		String goodCaB64 = "MIID6jCCAtKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwMzE4MDkzMTU1WhcNMjEwMTE4MDkzMTU1WjBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfUvDNM8lvv9P5pILP98HhhM0iiGMdw/MjJOqSKdA3Ss0xXT0UeYlr0blGBFt4yKHxfIAwR8BqLviT1CA0a6+PS8EDEC29txIRCPO+BscKlz4ZFlU9g2dGwA4Dl5ynEq0AP/TYjKl5RY+rGZT/Qx8Ea5OAr9MgQWWKuONFyo7dv4tM7FMTcHUL+hUqdQEpKXXsCOT5WYjtr3oYeu34Cal8m8YN/UmK70fGDwlRHLKgDIvcfZT3dkNOehabuez2Sj6kFkWNseQWeXSjzM1f2OH9idW9UmSQ7RvxDIAgKBYD/D9gGannG2SPZWQo+w5O9UhcE1N8Nc89CLCdJguVNF9hAgMBAAGjgdQwgdEwDgYDVR0PAQH/BAQDAgEGMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NybC9yb290LWNhLmNybDBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUHMAKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9yb290LWNhLmNydDAdBgNVHQ4EFgQU4tC4xPvJxRJqFXnjSqGn5Rzj5jYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAFJbVMStk22yRI6dczyzj6zyIh2noFa7STDW3oWg5UdXrjvWpCrw3OSqbF1UEF6X6FtDJfrXhmgyhVwVgHzH1n6+SXG3I/lOeAOKiCNjUA7uhenZuOgoVmWdfs+c9lIx8q7/f8L/kEePoDMLOYqhsSwfDhjELuq+2OOkMOqstuRyKPLQbK7nvf985W7qdjoggm4BHNm+RxkRkrLn1DxYqxnU+2ByZbZEWsqlPTgfRobBLbgPT7PMwVdwuZ6MzdVUsmBj82kGL2duAnzE117cTLmiEluUVXy/RskcHDcbhtOyOBzmQCKmXzafSiHTHtTUPC2XgpRwfwqad4jB+iMSL9A==";
		String rootCaB64 = "MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwMjE4MDkzMTU0WhcNMjEwMjE4MDkzMTU0WjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr35vEZwV4ynpmxadO6nuJTqhdPSDN0JIO3CFMU4CT/QQ2ZquuPxt4ImFW3mxXzsXkozrUV99Mwt8yRuYt6uJf761DkSjdPB/HVWNyLXVTq1hyiLsrfRlsklnZ08HSLcDK9gmuiHYyOlIl6V9dZkgscdH68mBQHzaS5Ve9P7p0QXBu1PaY/Mc65eSYUGTi75W6vBeX59mEGYAkUlr0LFdUf+Nr3kFlZ14Okh7w0y1NY8v8EUPQvMGnyrcAs+LBm5i65LoGdSQaIE9LiyYZvoFiC0CutY/aYWoLIhvjiLhMEmk+odU/6XOpvI7cUMrBVcLsvWrSmD/ju/mtaiPXfVV5AgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUMAns58WjMfSq9Xqlt1OwKEY8ze4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAYTtRueasFMQOuhKeJqI8QTonjxptdXpcOEx5lr7Hmo1+GDTuyKnGQIGWDl2WZoQuan9XITQsJSZWURY4yxsGhIxrM680M+FgZX/PQcgNOJDX00vAytnvZjssp45LDHMKbo9R9T5sjyjkxmMiQgWaQmKgt8biarZpzgTtlIG2U4aH6weuCNX8RW1nZHGMHjoR6lwV93jn8b8oZFqY7q0ISCR4gcIJ/Evqmshoau8vS8tIVD6FqECFWLKku+h9sO4LrYdDKLSZ4VAcZSv3jjGDbOmr4/L1XGF4WOWlrPNk3vVUH8ZbazNELzFPY24mrdZPDR9rNTE+rUZ4Nd1hhCKISg==";
		String ocspResponderB64 = "MIIDdjCCAl6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwMjE4MDkzMTU0WhcNMjEwMjE4MDkzMTU0WjBUMRcwFQYDVQQDDA5vY3NwLXJlc3BvbmRlcjEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtf7DwPE1lW3Vr0tTXzwN27S/ku3ZjyxAn7hFnNSR4ZuXmYISqxgKzruQVuHla1y/rtKQnh047Hel0sNnZwWY8sgVF9demBTGQdrUldCKL9bUFjZoHCwc31V0MMLHKfJq6G8eCxXGksA3C+2Gs0cmg7W2JNLVDzP+MWoS+iUT29HXn0m72REPz0ebWhCtaTT8PO+BFHqVKLMeFKcCKrqYdj8l1eLFXv/r6TZTrsdFChA3JFOjzhM4y1y4oASwaj1pLY/Kp7BRPJ/Gp+uYHuOzuKobKVInuBmWto+qxrcFsatPask4eRryaOak3D3ve4+7iVvP8+jUC8/hSnfbvblX1QIDAQABo1owWDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwkwHQYDVR0OBBYEFIwSKE1EIoKLkseZq31hTssa9UFmMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQELBQADggEBADGT8ZOTuWaNvvIR5EGjwgCMoOlmgeCFQByQT2Gtwf0dkbq8oV1NrJu0Sz9t1I8HNv8CfE1Nnlf0UszcyGSl3zeOYkF+OpgAkaM3vUZX9k4cBuZldtkcTySo6yiS3KlJz6sHxiaRiSljDXvCoH12A9kBvteF0GL8vFuzSR8FHC1Ayz3hwewl0V+SEN7+r1tQLKbLhrzTLvherALDd6SABQR13U0E0rbsoDOuo3dxI/BGa+MY8l+LLl3XT9/g4W5I1nuMCZYAdYsRnq4o2m+0EVT6RRMpQOeDKBTP17mgpQsyuy0MeFxpKs3UYjpftYM04gmOicrh20Zq5b4P30b5b8A=";

		CertificateToken goodUser = getCertificate(goodUserB64);
		CertificateToken goodUserBis = getCertificate(goodUserB64);
		CertificateToken goodCa = getCertificate(goodCaB64);
		CertificateToken rootCa = getCertificate(rootCaB64);
		CertificateToken ocspResponder = getCertificate(ocspResponderB64);

		assertEquals(goodUser, goodUser);
		assertEquals(goodUser, goodUserBis);
		assertNotEquals(goodUser, goodCa);

		List<CertificateToken> tokens = new ArrayList<>();
		tokens.add(goodUser);
		tokens.add(goodCa);
		tokens.add(rootCa);
		tokens.add(ocspResponder);
		assertEquals(4, tokens.size());

		tokens.remove(goodUserBis);
		assertEquals(3, tokens.size());
		assertTrue(tokens.contains(rootCa));
		assertTrue(tokens.contains(goodCa));
		assertTrue(tokens.contains(ocspResponder));
		assertFalse(tokens.contains(goodUser));

		Set<CertificateToken> set = new HashSet<>();
		set.add(ocspResponder);
		set.add(goodUser);
		set.add(goodUser);
		set.add(goodUserBis);
		set.add(goodCa);
		set.add(rootCa);
		assertEquals(4, set.size());

		Set<CertificateToken> copy = new HashSet<>(Collections.unmodifiableSet(set));

		set.remove(goodUserBis);
		assertEquals(3, set.size());
		assertTrue(set.contains(rootCa));
		assertTrue(set.contains(goodCa));
		assertTrue(set.contains(ocspResponder));
		assertFalse(set.contains(goodUser));
		assertFalse(set.contains(goodUserBis));

		assertTrue(copy.remove(goodUser));
		assertFalse(set.contains(goodUserBis));
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
}

