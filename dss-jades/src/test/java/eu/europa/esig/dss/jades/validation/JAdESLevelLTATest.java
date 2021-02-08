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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class JAdESLevelLTATest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/jades-lta.json");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateVerifier completeCertificateVerifier = getOfflineCertificateVerifier();
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwNjI5MDYxMTMxWhcNMjEwNjI5MDYxMTMxWjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZsOR/pEfaNLexVr4gSXIidJ+lsvfXOJEXiltJPH9Rp2x+vMMsaGIMYL8xcNSmuY73ki8JIofDpDRQ9RmgRLkuiXEymmiR18EG1gWXFNQbOVMTX/3AAWrjdtX47xxWHcHBtnIQHlFi/hRf8uR2fhraPqVk8x/9Fura8MNT9oGs3GooVYa233UXRO95/ewj1goSeklzmSjbgvTXRdHxxshHD5RsEd27t6KaZUfeDTZ2b0oRzEiplZl3JscM64qghjkPgjlF9nZ4CDm39WVuR9OKhj+0u+xcVrTjdiawkMKPTOpEwCq9jzpnji87K1Plg8D5wBCco6LKGDql4O7XCl6hAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU/6wUdEcUgkazbjfxX7qlbJFJujEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAmVtsZ1dqsY+jrDhRdokTUqLNXEIHArXvlKevRw6EDuCl1dEu/kGKfebonPALThf4ndH1U9UuEf3iCfADvHQuf6A9am3FPf0p2/PWCrOaip4Qwi4t8WqpKwpBGKVQxVFxHf1lTfhvYzoxW/kL8nG6tECChuuu7xD1kzxyRPaobLoiXTPws54LFFmd5H6P6BMzcP06+H3vu8cDFLbocp9+ZJXwxG54R0VMRBpcnlUNmGRPABJRdQUeS2wJBK29JjvKTMecXdEV008eQB4vPL9tE2aDHZHoJNbWV64Ls0BRDEijdqdiBbX8SgditYHNxdsuXC074F2yGyv45l5xGss2EA=="));
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIID/zCCAuegAwIBAgICA+owDQYJYIZIAWUDBAMOBQAwUjEVMBMGA1UEAwwMc2hhMy1yb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwNzI5MDYxMTE4WhcNMjEwNTI5MDYxMTE4WjBSMRUwEwYDVQQDDAxzaGEzLWdvb2QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANLs9GNGjbvzcPkQlBMNLjvA8iEdTjgpvYzIMvrajl2OAQBSEtPutCTGBA+Xze1YToeK/+othknzi1J5yVyKQEfVGa5JvCcrnWkpB7anpcY2eOIQKXbq5X23HlKZyV6/RmO5bd9zyVsGqryObsSSVH3XKUA0WkhPSRdqv3TpHGkRGv7OKUU5j4Xr6OdT3pL4TefGQ4MTqs/6JsfKHCI+jm6MLZ944yCoX9hHchfJaILKJaZrZ2qlJr2nSuMYP6IomcGejp+eVmxnmbaj4y75IGVaAgdkpx7ULKqp2kepEeyvqZvUyzMLyYA3qT30WA8o3HLufo3nfEhtcjYoBfHS9ssCAwEAAaOB3jCB2zAOBgNVHQ8BAf8EBAMCAQYwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL3NoYTMtcm9vdC1jYS5jcmwwUQYIKwYBBQUHAQEERTBDMEEGCCsGAQUFBzAChjVodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvc2hhMy1yb290LWNhLmNydDAdBgNVHQ4EFgQUV3D2n2PRcUWv4Sc8rZyb5Lyp3LswDwYDVR0TAQH/BAUwAwEB/zANBglghkgBZQMEAw4FAAOCAQEALPM/s+1WAfcxtseJE8sCk2MdJ0Xm3q5HLKoT+hZ3EZknbyJfHosK/9616eMulvL6QkC85/DRChKo7BAuakxhYUnEWbYk7GHaq+XAy1EqL6m1YDRyXBVRPnUr4Dgxy3g685juMH386VSjT0zTr4hpvbEAEv6v/PFnniUjfxjaRFpc/YX5AizmUfzThBxL0Q05tdwV4g5jQel1JM1L6FkWkpF+HrOXDj+cw1ueuNOVeRFt7OZzBjgOm2TJJaTmK8itF/cXYLrJMKQuOihZPM1yQAEfX6+qBR7iCqQ0M2vPO+uHcjRB9wJ5YN8SeJSJQRol84VpP6rJh2WGi95guAOa2w=="));
		completeCertificateVerifier.addTrustedCertSources(trustedCertificateSource);
		validator.setCertificateVerifier(completeCertificateVerifier);
		return validator;
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		
		boolean archiveTstFound = false;
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				assertEquals(ArchiveTimestampType.JAdES, timestamp.getArchiveTimestampType());
				archiveTstFound = true;
			}
		}
		assertTrue(archiveTstFound);
	}

}
