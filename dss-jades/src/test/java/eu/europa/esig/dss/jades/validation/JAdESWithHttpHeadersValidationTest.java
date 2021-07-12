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
package eu.europa.esig.dss.jades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class JAdESWithHttpHeadersValidationTest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		String jws = "eyJiNjQiOmZhbHNlLCJ4NXQjUzI1NiI6ImR5dFBwU2tKWXpoVGRQWFNXUDdqaFhnRzRrQ09XSVdHaWV" + 
				"zZHprdk5Melk9IiwiY3JpdCI6WyJzaWdUIiwic2lnRCIsImI2NCJdLCJzaWdUIjoiMjAyMC0wNC0yOV" + 
				"QxMjoyODoyOVoiLCJzaWdEIjp7InBhcnMiOlsiKHJlcXVlc3QtdGFyZ2V0KSIsIkNvbnRlbnQtVHlwZ" + 
				"SIsIlBTVS1JUC1BZGRyZXNzIiwiUFNVLUdFTy1Mb2NhdGlvbiIsIkRpZ2VzdCJdLCJtSWQiOiJodHRw" + 
				"Oi8vdXJpLmV0c2kub3JnLzE5MTgyL0h0dHBIZWFkZXJzIn0sImFsZyI6IlJTMjU2In0..oIQPqsAkfE" + 
				"3RiPKNHXVtut2KMQjrSX2rxaFgG78ULHbgDKdZqaTR0KagWV4Dlap5wif0cl45PTFRAI8Hpep02YCji" + 
				"qIc1vpxyXMzWv52JG68_ITGXwrXZ2I2f46YmoeWEKtQwCHrslSXDXywdwuw-0lHTEx04BO6WMt0Zy6y" + 
				"seGj7gMfseEJhw-4UO0o_aAIJtlHv2wQo8yeiKzWuE4dY1TBGny4CmfYWHWi4IR-2IGDH_bJjzzR7FU" + 
				"TJDrdOTk55GxJMaXyGeK3bViHgcO57yH9xx07hvWWebmhuDmnMOsbXxlRFQnQ7s5xpDSrpRlEHDgfcO" + 
				"xKrPB6dWGeSyWbJA";
		return new InMemoryDocument(jws.getBytes());
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		List<DSSDocument> detachedContents = new ArrayList<>();
		detachedContents.add(new HTTPHeader("(request-target)", 
				"post https://api.testbank.com/v1/payments/sepa-credit-transfers"));
		detachedContents.add(new HTTPHeader("Content-Type", "application/json"));
		detachedContents.add(new HTTPHeader("X-Request-ID", "99391c7e-ad88-49ec-a2ad-99ddcb1f7721"));
		detachedContents.add(new HTTPHeader("PSU-IP-Address", "192.168.8.78"));
		detachedContents.add(new HTTPHeader("PSU-GEO-Location", "GEO:52.506931,13.144558"));
		detachedContents.add(new HTTPHeader("PSU-User-Agent", 
				"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0"));
		detachedContents.add(new HTTPHeader("Date", "Fri, 3 Apr 2020 16:38:37 GMT"));
		detachedContents.add(new HTTPHeader("Digest", "SHA-256=+xeh7JAayYPh8K13UnQCBBcniZzsyat+KDiuy8aZYdI="));
		return detachedContents;
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		AbstractJWSDocumentValidator validator = (AbstractJWSDocumentValidator) super.getValidator(signedDocument);
		
		CertificateToken signingCert = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIIkzCCBnugAwIBAgIDAOqWMA0GCSqGSIb3DQEBCwUAMIGoMQswCQYDVQQGEwJJ" + 
				"VDEYMBYGA1UECgwPSW5mb0NlcnQgUy5wLkEuMSkwJwYDVQQLDCBRdWFsaWZpZWQg" + 
				"VHJ1c3QgU2VydmljZSBQcm92aWRlcjEaMBgGA1UEYQwRVkFUSVQtMDc5NDUyMTEw" + 
				"MDYxODA2BgNVBAMML0luZm9DZXJ0IFF1YWxpZmllZCBFbGVjdHJvbmljIFNpZ25h" + 
				"dHVyZSBDQSAzIENMMB4XDTIwMDQxNTE1MTU1NloXDTIyMDQxNTAwMDAwMFowgasx" + 
				"HTAbBgNVBGEMFFBTRElULUJJLTAxMjM0NTY3ODkwMQswCQYDVQQGEwJJVDE0MDIG" + 
				"A1UECgwrQWdhaW5zdCB0aGUgd2luZCBwYXltZW50IGluc3RpdHV0aW9uIFMucC5B" + 
				"LjEPMA0GA1UEBwwGVmVuaWNlMRUwEwYDVQQLDAxQU0QyIEVuYWJsZXIxHzAdBgNV" + 
				"BAMMFkFnYWluc3QgdGhlIHdpbmQgZVNlYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IB" + 
				"DwAwggEKAoIBAQCmrS4z53Pjie6Nc4JqlOIM+a2ysSM89LZwrr1iN3SPp/rbSe2N" + 
				"KvFtMd7EO1X0UZBTFbePX5qm8iBqXHBYKgJG53xcfcgKGf9WEB63XyLag4Xg3ZsM" + 
				"O6xISNxsEwudMCaH5/Q2mog+Wy0N8CiYGm1yz7MCczjGCgDGONFgrbHppkU1T9TY" + 
				"BnNymlSqajJmf+XcMbVMQr42l9UfKel5+IJ8KHHC33niRsxQYYJQNx712xKxdWWZ" + 
				"u5tWud2aboopPppkl9fniSwr9pEYsRLlj7nnEIpeZManujMALiTJ3I3z+Xcxt8L9" + 
				"gGjy7j4erxMU6gAGf42Jny4mxIrD6tnT0Jm3AgMBAAGjggO/MIIDuzAJBgNVHRME" + 
				"AjAAMIIBBAYDVR0fBIH8MIH5MIH2oIHzoIHwhilodHRwOi8vY3JsY2wuaW5mb2Nl" + 
				"cnQuaXQvY2EzL3FjL0NSTDAyLmNybIaBwmxkYXA6Ly9sZGFwY2wuaW5mb2NlcnQu" + 
				"aXQvY24lM0RJbmZvQ2VydCUyMFF1YWxpZmllZCUyMEVsZWN0cm9uaWMlMjBTaWdu" + 
				"YXR1cmUlMjBDQSUyMDMlMjBDTCUyMENSTDAyLG91JTNEUXVhbGlmaWVkJTIwVHJ1" + 
				"c3QlMjBTZXJ2aWNlJTIwUHJvdmlkZXIsbyUzRElORk9DRVJUJTIwU1BBLGMlM0RJ" + 
				"VD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MGUGA1UdIAReMFwwCQYHBACL7EAB" + 
				"ATBPBgYrTCQBAS8wRTBDBggrBgEFBQcCARY3aHR0cDovL3d3dy5maXJtYS5pbmZv" + 
				"Y2VydC5pdC9kb2N1bWVudGF6aW9uZS9tYW51YWxpLnBocDBvBggrBgEFBQcBAQRj" + 
				"MGEwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3NwY2wuY2EzLmluZm9jZXJ0Lml0LzAz" + 
				"BggrBgEFBQcwAoYnaHR0cDovL2NlcnRjbC5pbmZvY2VydC5pdC9jYTMvcWMvQ0Eu" + 
				"Y3J0MIHGBggrBgEFBQcBAwSBuTCBtjAIBgYEAI5GAQEwCwYGBACORgEDAgEUMBMG" + 
				"BgQAjkYBBjAJBgcEAI5GAQYCMD4GBgQAjkYBBTA0MDIWLGh0dHBzOi8vd3d3LmZp" + 
				"cm1hLmluZm9jZXJ0Lml0L3BkZi9QS0ktRFMucGRmEwJlbjBIBgYEAIGYJwIwPjAm" + 
				"MBEGBwQAgZgnAQIMBlBTUF9QSTARBgcEAIGYJwEDDAZQU1BfQUkMDUJhbmsgb2Yg" + 
				"SXRhbHkMBUlULUJJMA4GA1UdDwEB/wQEAwIGQDCB1QYDVR0jBIHNMIHKgBRUM8Ad" + 
				"mZiQ/fsJlGf4HcwJUqEPpqGBrqSBqzCBqDELMAkGA1UEBhMCSVQxGDAWBgNVBAoM" + 
				"D0luZm9DZXJ0IFMucC5BLjEpMCcGA1UECwwgUXVhbGlmaWVkIFRydXN0IFNlcnZp" + 
				"Y2UgUHJvdmlkZXIxGjAYBgNVBGEMEVZBVElULTA3OTQ1MjExMDA2MTgwNgYDVQQD" + 
				"DC9JbmZvQ2VydCBRdWFsaWZpZWQgRWxlY3Ryb25pYyBTaWduYXR1cmUgQ0EgMyBD" + 
				"TIIBATAdBgNVHQ4EFgQULUnlOpVpVXd+NFQU/DCgkJ/YWRcwDQYJKoZIhvcNAQEL" + 
				"BQADggIBABvNa8X0kXAcOmVzGyd13qBRDx7lJLmyQr8Z/r4dWtB9u/uRQ9YOTETY" + 
				"cxT3fhAbgzMdjiQ4nAo6egIm3xCrZ5y9xVmIsVhjYc90k/kxpp2oW3vjP2pZTJbM" + 
				"SF5DrPseChYTSsSZ7K629twX9Obp4T67AfpnqTjH7X5DnT49BAkNkVBWl4Job57f" + 
				"GJdAgnSlRpM97umMYbticpGH936HbBuxg+G0kAfwF4GUXDBUmEeXoUEs7FuWoMXk" + 
				"R3JGEK2t1qW5lJ5EjwEXRWehe4rz/nteR8bmwZNSx2rk9P+3oQehU+iIHhyVFF0H" + 
				"VxKPHyA0hP5jI3kdjujf/IoESx+99Kn5nDMHHDjPoo+HhK++ERV6MeWB0dlwqzXW" + 
				"sJYRz5KvqXoUFrwEFKtHwBUwOb+4rENU07fGCC/36/d0OHExPODwLFTCD+ZwdcN+" + 
				"pAnyLEhBRwhfd3SrTrgHb6JoXloe80JaxiGC7iKgUw15Z/YhRFw9jydsFg1vg+MO" + 
				"R1Q0nRKz5aYFCPqHbBocW4IqDQsuQYzXRoTvBK2qpG9c5e+LRFgeCe1jWBhi0Nai" + 
				"fl8bmzhHAR7WwdOOtQ9ko7w+cW015Z2ge4JYEMQkMspv5o7fllebGtF2w8gzJkrT" + 
				"iVbXc/IoD8/DOKU6nHDxkkKSC+Le89cdftvVmlfxyHf3LS2XfFzb");

		KidCertificateSource certificateResolver = new KidCertificateSource();
		certificateResolver.addCertificate(signingCert);
		// useless
		certificateResolver.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhkiG9w0BAQUFADB1MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEoMCYGA1UEAwwfRUUgQ2VydGlmaWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMB4XDTExMDMxODEwMjE0M1oXDTI0MDMxODEwMjE0M1owgZ0xCzAJBgNVBAYTAkVFMQ4wDAYDVQQIEwVIYXJqdTEQMA4GA1UEBxMHVGFsbGlubjEiMCAGA1UEChMZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czENMAsGA1UECxMET0NTUDEfMB0GA1UEAxMWU0sgT0NTUCBSRVNQT05ERVIgMjAxMTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAihvGyhMVrgReHluKln1za6gvCE/mlSREmWjJFpL9llvuEUZoPFIypYA8g5u1VfgkeW5gDq25jAOq4FyXeDGIa+pJn2h0o2Wc2aeppVG/emfGm/jA8jjeyMrwH8fAJrqVQ7c9X2xSwJEch/P2d8CfMZt5YF6gqLtPvG1b+n6otBZA5wjIFfJ/inJBMUvqHSz3+PLfxO2/T3Wyk/c8M9HIMqTelqyiMGRgWehiU1OsL9armv3dQrHs1wm6vHaxfpfWB9YAFpeo9aYqhPCxVt/zo2NQB6vxyZS0hsOrXL7SxRToOJaqsnvlbf0erPPFtRHUvbojYYgl+fzlz0Jt6QJoNwIDAQABo4IBHTCCARkwEwYDVR0lBAwwCgYIKwYBBQUHAwkwHQYDVR0OBBYEFKWhSGFt537NmJ50nCm7vYrecgxZMIGCBgNVHSAEezB5MHcGCisGAQQBzh8EAQIwaTA+BggrBgEFBQcCAjAyHjAAUwBLACAAdABpAG0AZQAgAHMAdABhAG0AcABpAG4AZwAgAHAAbwBsAGkAYwB5AC4wJwYIKwYBBQUHAgEWG2h0dHBzOi8vd3d3LnNrLmVlL2FqYXRlbXBlbDAfBgNVHSMEGDAWgBQS8lo+6lYcv80GrPHxJcmpS9QUmTA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vd3d3LnNrLmVlL3JlcG9zaXRvcnkvY3Jscy9lZWNjcmNhLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAw2sKwvTHtYGtD8Jw9mNUuj/mWiBSBEBeY2LhW8V6tjBPAPp3s6iWOh0FbVR2LUyrqRwgT3fyWiGsiDm/6cIqM+IblLp/8ztfRQjquhW6XCD9SK02OQ9ZSdBwcmoAApZLGXQC34wdgmV/hLTTNxONnDACBKz9U+Dy9a4ZT4tpNkbH8jq/BMne8FzbvRt1bjpXBP7gjLX+zdx8/hp0Wq4tD+f9NVX0+vm9ahEKuzx4QzPnSB7hhWM9OnLZT7noRQa+KWk5c+e5VoR5R2t7MjVl8Cd+2llxiSxqMSbU5/23BzAKgN+NQdrBZAzpZ7lfaAuLFaICP+bAm6uW2JUrM6abOw=="));
		validator.setSigningCertificateSource(certificateResolver);
		
		CertificateToken caCert = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIHaDCCBVCgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBqDELMAkGA1UEBhMCSVQx" + 
				"GDAWBgNVBAoMD0luZm9DZXJ0IFMucC5BLjEpMCcGA1UECwwgUXVhbGlmaWVkIFRy" + 
				"dXN0IFNlcnZpY2UgUHJvdmlkZXIxGjAYBgNVBGEMEVZBVElULTA3OTQ1MjExMDA2" + 
				"MTgwNgYDVQQDDC9JbmZvQ2VydCBRdWFsaWZpZWQgRWxlY3Ryb25pYyBTaWduYXR1" + 
				"cmUgQ0EgMyBDTDAeFw0xNjExMzAxNjA2MzJaFw0zMjExMzAxNzA2MzJaMIGoMQsw" + 
				"CQYDVQQGEwJJVDEYMBYGA1UECgwPSW5mb0NlcnQgUy5wLkEuMSkwJwYDVQQLDCBR" + 
				"dWFsaWZpZWQgVHJ1c3QgU2VydmljZSBQcm92aWRlcjEaMBgGA1UEYQwRVkFUSVQt" + 
				"MDc5NDUyMTEwMDYxODA2BgNVBAMML0luZm9DZXJ0IFF1YWxpZmllZCBFbGVjdHJv" + 
				"bmljIFNpZ25hdHVyZSBDQSAzIENMMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC" + 
				"CgKCAgEAzBb1EC0qvtMBWs6T9j8tAQHazdAygG8rmea81wo0PZF3oSLvMgSZpfiH" + 
				"xPk2GTtseAQUgqLe5oH4g1w2DmsrGJ71cen76Exd7fCIOPllWjbJW6vNrEB4kono" + 
				"vmZjfruAekRrBs9EZaff+vmDle45hJxtyNvofFb0k9465QlhBKhrwpJyHH7wWIvV" + 
				"KQ0kxP/aIdH5R6fJF9Nhf+US1CsxOiVjZVzGtQaZfkbZSXgzLYsj4l5A1eR6vobf" + 
				"qgiRpXcMdzkzpTmYCRz7kHpN0wxpWGvJUWwoSM3ndhP/G1LNW+r29Go9Il9wg84a" + 
				"faOALLyBDwHKJ5yODBPt3f9oandcHagCND0jHuuBd9nhgvVfusYA9WB17dJ+TwD1" + 
				"WiQeMs8VgFDIu58TfW1K9jLKYap9/dRut9We7JQQDi0KBPv+dlW01wFM6P2O4ZOu" + 
				"3aP7AOvISeDFmeNkwpUuiuvuTBPX1hPqZOu0nxhM6bb1qgdlfiEmuY0pCtpK0vFw" + 
				"aXZEIDEAj2y3lhX0hUycRFB6e0usvuUpYiiA3n/w6qb+/+r49L8cO69/FEk7+Irq" + 
				"YoOOQmXoxxtkzPLe0cwvpl92Fu0YqTI7QxVPne08Os8YtnbNmGwxNLpK6onh6NIk" + 
				"lE/wLWVUET4WgBGSuiPCM8VBKdWLFs93PRCiB5w9UQMWsXRwG4sCAwEAAaOCAZkw" + 
				"ggGVMA8GA1UdEwEB/wQFMAMBAf8wWAYDVR0gBFEwTzBNBgRVHSAAMEUwQwYIKwYB" + 
				"BQUHAgEWN2h0dHA6Ly93d3cuZmlybWEuaW5mb2NlcnQuaXQvZG9jdW1lbnRhemlv" + 
				"bmUvbWFudWFsaS5waHAwgfgGA1UdHwSB8DCB7TCB6qCB56CB5IYnaHR0cDovL2Ny" + 
				"bGNsLmluZm9jZXJ0Lml0L2NhMy9xYy9BUkwuY3JshoG4bGRhcDovL2xkYXBjbC5p" + 
				"bmZvY2VydC5pdC9jbiUzREluZm9DZXJ0JTIwUXVhbGlmaWVkJTIwRWxlY3Ryb25p" + 
				"YyUyMFNpZ25hdHVyZSUyMENBJTIwMyUyMENMLG91JTNEUXVhbGlmaWVkJTIwVHJ1" + 
				"c3QlMjBTZXJ2aWNlJTIwUHJvdmlkZXIsbyUzRElORk9DRVJUJTIwU1BBLGMlM0RJ" + 
				"VD9hdXRob3JpdHlSZXZvY2F0aW9uTGlzdDAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0O" + 
				"BBYEFFQzwB2ZmJD9+wmUZ/gdzAlSoQ+mMA0GCSqGSIb3DQEBCwUAA4ICAQBnt6Kw" + 
				"QYzlZvrknDKxaSSkSyNml10ycS6aTZVUAKdAQTh7k16BsRudjKQ4zasT592qxnO6" + 
				"Z8wFOU20O9Y+cMMQxUw8uVcBGPIvxGaScXJbZrQb5O5kNkLEN37PaA6y9R49jx+J" + 
				"mefKsnpkhA9+Ng53F79/0sv425fCMaftYeKz1vhKHizNs+a016O1A0ilg2yTSr3P" + 
				"sTYJpfstDfARFAQot2S0Z8pR45AYG99ZKKb8KwSgMO49TBOlJATlgiYgUKejY4sv" + 
				"X8HcF5HG348N3HiCeBkF3oZINBVfUa7QBrrmpp1lT1Pr5rhl9qGjt0R4JeQnk68+" + 
				"IaJOzXNCYMxv4pi3Ot3tdhzhgc+9/BZIS73Ch/CiHHYwdkQ8uVumVqrRzsuzirmu" + 
				"TlPtHoShNCvMIi66LK31vwMrlG53AIDJEtWxZUJJb958hyY0YY+Fj38gPhP6Bm8M" + 
				"DAk/qBbQ/ryC8912uyGPXnyLS8/ubY8RmXv0WtHI2O8IQEhoBNeu2xSszIkcKqPA" + 
				"hD12W5y3ITbbi7g4NOANaev4AYPLxm+BAqX8/MRk8fHnPxdTIDA1LpTebvdNDcj6" + 
				"76bF3PL4WM0WECYbn3Xazvw74+OVWRCLOzsn1Z1eQXlmMLDqTwwC8Ss7HtoJuNL4" + 
				"Fqs2uC9VK5Yc2WDU9X+IWBIwNVBIB5gfn3qWqw==");
		
		CommonCertificateSource adjunctCertificateSource = new CommonCertificateSource();
		adjunctCertificateSource.addCertificate(caCert);
		
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.addAdjunctCertSources(adjunctCertificateSource);
		
		validator.setCertificateVerifier(certificateVerifier);
		
		return validator;
	}
	
	@Override
	protected void checkCertificateChain(DiagnosticData diagnosticData) {
		super.checkCertificateChain(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature.getSigningCertificate());
		assertEquals(2, signature.getCertificateChain().size());
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		// useless certificate is not added to UsedCertificates
		assertEquals(2, diagnosticData.getUsedCertificates().size());

		for (CertificateWrapper cert : diagnosticData.getUsedCertificates()) {
			assertFalse(cert.getSources().contains(CertificateSourceType.SIGNATURE));
		}
	}

}
