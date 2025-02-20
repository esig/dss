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
package eu.europa.esig.dss.spi.x509.revocation.crl;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OfflineCRLSourceTest {

	@Test
	void test() {

		String crlB64 = "MIIBbTBXMA0GCSqGSIb3DQEBBQUAMCgxCzAJBgNVBAYTAkJFMRkwFwYDVQQDExBCZWxnaXVtIFJvb3QgQ0EyFw0xNDA3MDExMTAwMDBaFw0xNTAxMzExMTAwMDBaMA0GCSqGSIb3DQEBBQUAA4IBAQClCqf+EHb/ZafCIrRXdEmIOrHV0fFYfIbLEWUhMLIDBdNgcDeKjUOB6dc3WnxfyuE4RzndBbZA1dlDv7wEX8sxaGzAdER166uDS/CF7wwVz8voDq+ju5xopN01Vy7FNcCA43IpnZal9HPIQfb2EyrfNu5hQal7WiKE7q8PSch1vBlB9h8NbyIfnyPiHZ7A0B6MPJBqSCFwgGm+YZB/4DQssOVui0+kBT19uUBjTG0QEe7dLxZTBEgBowq5axv93QBXe0j+xOXZ97tlU2iJ51bsLY3E134ziMV6hKPsBw6ARMq/BF64P6axLIUOqdCRaYoMu2ekfYSoFuaM3l2o79aw";

		String certToValidateB64 = "MIIEBTCCAu2gAwIBAgILBAAAAAABQeUqkm4wDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMTMxMDIzMTEwMDAwWhcNMTkwMTIzMTEwMDAwWjBjMQswCQYDVQQGEwJCRTENMAsGA1UEBRMEMjAxNDEjMCEGA1UEChMaQmVsZ2l1bSBGZWRlcmFsIEdvdmVybm1lbnQxIDAeBgNVBAMTF1RpbWUgU3RhbXBpbmcgQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuurzcUZ9xj0Hxj8pzLPSdodxbl9hTzmvVFjVwkPlO/CKItuMv5jdX78vkJyxDoCIzlaydC8iX6LKVvbKWS8DHU4Q9vUg9jlyPrG3pM8/7uMKEiVJlo1Q7G/j3ycVIfKW5JgLEUkkA7prtjxumaUaNtoSoLXVbHU+4qIVLuBOq7dYwZN0oftYM6cUEslqDi8OSAZVyPYvUNI7klcQRh28duuMyUXhOzu4neBz49uSA5c3nAIHJxJH+zsIEIZ/rv2+oiFsN3NRy8mu8sHwOR1bf81SP73C6Gsgx0cjb4JaEvAdEXayOx5YjIkp8p9rF0sMHbimYy6Xhg6uAzObjFrQtwIDAQABo4H0MIHxMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBDBgNVHSAEPDA6MDgGBmA4CQEBBTAuMCwGCCsGAQUFBwIBFiBodHRwOi8vcmVwb3NpdG9yeS5wa2kuYmVsZ2l1bS5iZTAdBgNVHQ4EFgQUhy+xl8l/bUtfYofrFHxPI0hLRJIwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5wa2kuYmVsZ2l1bS5iZS9iZWxnaXVtMi5jcmwwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBSFiuv0xbu+DlkDlN7WgAEV4xCcOTANBgkqhkiG9w0BAQUFAAOCAQEAKtng/BMJwJ4moDPdh0wJbMcDupg7Cr3PboLqNiVtJHtojtgya5+LDfIpDaBt054es/OKV3fNd40LU1eNBj0flU0SNgxwRqqWwBjdpBj9XCZsLsTlCjLDG7HJq6toyAfXYjHBj3KldUQS2g4wf3nxeQgDbLTs28MhpJWN9FCk2DJ63aPEbAZ/HA20NPAb86KM/LhO2AlkDwhpP510ih1dBWjiwNRrkrmxInW+PCQmBGR60rqRs5f8naosyR8URDz/wHiQ4Arn/HrX/KVZ2HMD8pt1IZY+5LuIuA2fn0hNCQyrGZoa3HNqIIP5zfavw0Tp+jDKLNNSsi5L8CP128lkug==";
		String certWrongKeySizeB64 = "MIIFjjCCA3agAwIBAgIIOyEC3pZbHakwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTMwHhcNMTMwNjI2MTIwMDAwWhcNMjgwMTI4MTIwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKjyAZ2Lg8kHoIX7JLc3BeZ1Tzy9MEv7Bnr59xcJezc/xJJdO4V3bwMltKFfNvqsQ5H/GQADFJ0GmTLLPDI5AoeUjBubRZ9hwruUuQ11+vhtoVhuEuZUxofEIU2yJtiSOONwpo/GIb9C4YZ5h+7ltDpC3MvsFyyordpzgwqSHvFwTCmls5SpU05UbF7ZVPcfVf24A5IgHLpZTgQfAvnzPlm++eJY+sNoNzTBoe6iZphmPbxuPNcJ6slV8qMQQk50/g+KmoPpHX4AvoTr4/7TMTvuK8jS1dEn+fdVKdx9qo9ZZRHFW/TXEn5SrNUu99xhzlE/WBurrVwFoKCWCjmO0CnekJlw0NTr3HBTG5D4AiDjNFUYaIcGJk/ha9rzHzY+WpGdoFZxhbP83ZGeoqkgBr8UzfOFCY8cyUN2db6hpIaK6Nuoho6QWnn+TSNh5Hjui5miqpGxS73gYlT2Qww16h8gFTJQ49fiS+QHlwRw5cqFuqfFLE3nFFF9KIamS4TSe7T4dNGY2VbHzpaGVT4wy+fl7gWsfaUkvhM4b00DzgDiJ9BHiKytNLmzoa3Sneij/CKur0dJ5OdMiAqUpSd0Oe8pdIbmQm1oP5cjckiQjxx7+vSxWtacpGowWK8+7oEsYc+7fLt3GD6q/O5Xi440Pd/sFJmfqRf3C1PPMdBqXcwjAgMBAAGjgbswgbgwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wQgYDVR0gBDswOTA3BgVgOAoBATAuMCwGCCsGAQUFBwIBFiBodHRwOi8vcmVwb3NpdG9yeS5laWQuYmVsZ2l1bS5iZTAdBgNVHQ4EFgQUuLxsAI9bGYWdJQGc8BncQI7QOCswEQYJYIZIAYb4QgEBBAQDAgAHMB8GA1UdIwQYMBaAFLi8bACPWxmFnSUBnPAZ3ECO0DgrMA0GCSqGSIb3DQEBBQUAA4ICAQBFYjv/mKX+VcyxEacckgx4L8XvFkIFPXzjEnDnAtCCkROU/k5n1jjVK+ODOn+Q4kJg6Nd7K47+zTXcrSe1tB2gVMsyaCN9scy4phLX1qT48sThCjUtooxfIoRycpdlf14HcUPCYlASTCapZU0MnAbzfpzxm49Ik/A2JWxAhxXVRHwOu3TMGiQ4W/VyVawxjwQMO8TneBDombmkXsI9bI0OxWUh2A5dKlqu0sYvE0dz8xDxr9ZkmZqYcPIKizCZlaP1ZsSlCi5S31gn3EUP+fd21q6ZXgU+50/qgoh/0UUaHRpedPQBES/FYc2IQZ2XjhmeTwM+9Lk7tnzHeHp3dgCoOfceyPUaVkWiXMWcNAvvkDVELvXfJpRxwcRfS5Ks5oafOfj81RzGUbmpwl2usOeCRwdWE8gPvbfWNQQC8MJquDl5HdeuzUesTXUqXeEkyAOo6YnF3g0qGcLI9NXusji1egRUZ7B4XCvG52lTB7Wgd/wVFzS3f4mAmYTGJXH+N/lrBBGKuTJ5XncJaliFUKxGP6VmNyaaLUF5IlTqC9CGHPLSXOgDokt2G9pNwFm2t7AcpwAmegkMNpgcgTd+qk2yljEaT8wf953jUAFedbpN3tX/3i+uvHOOmWjQOxJg2lVKkC+bkWa2FrTBDdrlEWVaLrY+M+xeIctrC0WnP7u4xg==";
		String caCertB64 = "MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=";

		CertificateToken certToValidate = DSSUtils.loadCertificateFromBase64EncodedString(certToValidateB64);

		OfflineCRLSource crlSource = new ExternalResourcesCRLSource(new InMemoryDocument(Utils.fromBase64(crlB64)));
		
		assertEquals(0, crlSource.getRevocationTokens(certToValidate, certToValidate).size());
		
		CertificateToken certWrongKeySize = DSSUtils.loadCertificateFromBase64EncodedString(certWrongKeySizeB64);
		assertEquals(0, crlSource.getRevocationTokens(certToValidate, certWrongKeySize).size());

		CertificateToken caCert = DSSUtils.loadCertificateFromBase64EncodedString(caCertB64);
		assertEquals(1, crlSource.getRevocationTokens(certToValidate, caCert).size());
		assertEquals(1, crlSource.getRevocationTokens(certToValidate, caCert).size());

	}

	@Test
	void npe() {
		OfflineCRLSource crlSource = new ExternalResourcesCRLSource(new DSSDocument[0]);
		assertThrows(NullPointerException.class, () -> crlSource.getRevocationTokens(null, null));
	}

}
