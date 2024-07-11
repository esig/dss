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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESDoubleLTAInOneContainerTest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/double-lta-in-container.json");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateVerifier completeCertificateVerifier = getOfflineCertificateVerifier();
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkxMDE0MDUzODQ0WhcNMjExMDE0MDUzODQ0WjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDULeex4u8ebUQEfm0V0em+r1AqpR11+84XlxFJyEMDOhCbPOOQI68HVIVWt/GX7naFUoiAPm0IhlAYlq0/amBxg/Q8wW9a6KZc4o3DFgGIBFNEOYHCSwJPQ8EtcSmWZ/+Fgb7+lPffbTCucaOgax5VRFQp6c0fswCmcA9jukxeFCDOz8HNQqBiKvuRmkAj8NmwgQHx/Sndo7YdkalPr2qJ+gBRdg6JANIWuYahxixypqP5He+3pb0ghjWOjCnaIg2K2PQUy6i8YTnagwyGS/FxhXpdLatdUhjUdgkvLn1ZyxqvCbOZsiUx55p2FljR3fSUgt9+VOwC4WzZVLtZHZejAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUXB8V7Y9AxDcPJ5i36BC54z8jWyowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAOem7HjwO2cGZlFYSAGby13r8gTkY9Dtq1GbsB+kawdUt6d86tmAw3zNKaPb4qAuZtEeM5tVfW2bj1eN+FzI+T9ZDDEnU50Y9x+DC6q3ZBPk46x0XK+7frnyDkhikRyZ5yss6dqoo8nKgIQUEXdeOky6cK2ybUcGUwzgVn/GalLEcA6zILHp7NAsOxzbwsCEgeWY9CBW5/3GAp/2qo1NNPXukazd9/a5KOeRht2iRjXISUWWJKFHsAJtsmZrul+hfTGorjc6rG+PMNnWK7X5rB/6ZwSVG6naxuoaunIrp99rDuSw9k8pvcyXzofaXDlFYPe1vVyc14Bhtca8A4YI6Jw=="));
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIID/zCCAuegAwIBAgICBLAwDQYJKoZIhvcNAQELBQAwUDETMBEGA1UEAwwKZWUtcm9vdC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTE5MTExNDA2MzgzM1oXDTIxMDkxNDA1MzgzM1owUTEUMBIGA1UEAwwLZWUtZ29vZC10c2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALPF8I5hvB0c4Ds38lvQJUDUqe3/amaj+oZjtkjO3+G7oZCwaCBnJ2F0izFzRrzkm3RXCm+46Oeq5BDiBWljyFmntK5hnMCs57wZtkS2B4FdFHK//uvBOdFwU8aiUe1sl3kKe7ulbLKZ/0i/CBrhjNxNfmGjBpCinzBDdP2yaIwe1y56gupMfItn2YJsr27P/o8oqYPeFc55lG1UJpGmI+GcphBS3cuv2jjrqaiOqffBF9uUfjQbaFIlcPiEy3KxjULpFfyTIOBKR2yelWPB5hYCkM1G8iMzxgJPHe3sVxghM2w6QhIztBmT8ER5ZdM5jOKF+AeIG533UH+KwpPjmW8CAwEAAaOB4TCB3jAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL2VlLXJvb3QtY2EuY3JsME8GCCsGAQUFBwEBBEMwQTA/BggrBgEFBQcwAoYzaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3J0L2VlLXJvb3QtY2EuY3J0MB0GA1UdDgQWBBRdOcDuQk8iA41KiMuF2+OPAGLg0TANBgkqhkiG9w0BAQsFAAOCAQEAXYtZNHL2KuaSC713Wzre3GVJKQ+M10qncLgERlWhnUlmJhxr9Sidz27PyOr5VV+9qxpNgKmWE3QyQH/+Y6fqeFqJaa0QqXiRcaMNCfcLiA7/JlSjkR6WwztOacKepQpk7iCoSUzCjqcrs+1ujrdO7RumIt3y2xsRh630boJQJS77j+POiPreO65BQr27AARIZATGoiBgPRDfTlmR9jKGSNwyP8A572oCJmgJzInBlUZDxnUoE+lrzTD0lycVKJ44tcR3UmaOtjaNzdmF3Riu5DTj6RIR5n16KYK3YtOevbEhEVjxTD7yHPT0WpGS+WzPQXqtCmXFzVkKqQYz9IGbIA=="));
		completeCertificateVerifier.addTrustedCertSources(trustedCertificateSource);
		validator.setCertificateVerifier(completeCertificateVerifier);
		return validator;
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(3, timestampList.size());
		String signatureTstId = timestampList.get(0).getId();
		
		int archiveTstCounter = 0;
		List<String> timestampedObjectIds = null;
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				assertEquals(ArchiveTimestampType.JAdES, timestamp.getArchiveTimestampType());
				assertTrue(Utils.isCollectionNotEmpty(timestamp.getTimestampedObjects()));
				++archiveTstCounter;
				List<String> currentTimestampedObjectIds = timestamp.getTimestampedObjects().stream().map(o -> o.getToken().getId()).collect(Collectors.toList());
				if (timestampedObjectIds == null) {
					timestampedObjectIds = currentTimestampedObjectIds;
				} else {
					assertEquals(timestampedObjectIds, currentTimestampedObjectIds);
				}
				assertTrue(currentTimestampedObjectIds.contains(signatureTstId));
			}
		}
		assertEquals(2, archiveTstCounter);
		assertNotEquals(timestampList.get(0).getSigningCertificate().getId(), timestampList.get(1).getSigningCertificate().getId());
		
	}

}
