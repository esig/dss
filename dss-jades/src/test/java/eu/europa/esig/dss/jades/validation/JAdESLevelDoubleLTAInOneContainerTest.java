package eu.europa.esig.dss.jades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class JAdESLevelDoubleLTAInOneContainerTest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/double-lta-in-container.json");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateVerifier completeCertificateVerifier = getOfflineCertificateVerifier();
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwNjI5MDYxMTMxWhcNMjEwNjI5MDYxMTMxWjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZsOR/pEfaNLexVr4gSXIidJ+lsvfXOJEXiltJPH9Rp2x+vMMsaGIMYL8xcNSmuY73ki8JIofDpDRQ9RmgRLkuiXEymmiR18EG1gWXFNQbOVMTX/3AAWrjdtX47xxWHcHBtnIQHlFi/hRf8uR2fhraPqVk8x/9Fura8MNT9oGs3GooVYa233UXRO95/ewj1goSeklzmSjbgvTXRdHxxshHD5RsEd27t6KaZUfeDTZ2b0oRzEiplZl3JscM64qghjkPgjlF9nZ4CDm39WVuR9OKhj+0u+xcVrTjdiawkMKPTOpEwCq9jzpnji87K1Plg8D5wBCco6LKGDql4O7XCl6hAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU/6wUdEcUgkazbjfxX7qlbJFJujEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAmVtsZ1dqsY+jrDhRdokTUqLNXEIHArXvlKevRw6EDuCl1dEu/kGKfebonPALThf4ndH1U9UuEf3iCfADvHQuf6A9am3FPf0p2/PWCrOaip4Qwi4t8WqpKwpBGKVQxVFxHf1lTfhvYzoxW/kL8nG6tECChuuu7xD1kzxyRPaobLoiXTPws54LFFmd5H6P6BMzcP06+H3vu8cDFLbocp9+ZJXwxG54R0VMRBpcnlUNmGRPABJRdQUeS2wJBK29JjvKTMecXdEV008eQB4vPL9tE2aDHZHoJNbWV64Ls0BRDEijdqdiBbX8SgditYHNxdsuXC074F2yGyv45l5xGss2EA=="));
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIID/zCCAuegAwIBAgICBLAwDQYJKoZIhvcNAQELBQAwUDETMBEGA1UEAwwKZWUtcm9vdC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTE5MDcyOTA2MTEyMloXDTIxMDUyOTA2MTEyMlowUTEUMBIGA1UEAwwLZWUtZ29vZC10c2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL987tVg6gpMfaLfPjsyAgqL/yMtq9EpCFCYKkJEFJb5vlXI+dQJE1b8jpb9TaLcLigrSDX7tRypiqrlNqFXr1sv+sMQ6N9X5sLAqjWF/kZkIh1M9GsxTsGOaIIHpHeCYsh7SeBdgNLbzLwueqabNy4+v0S40i+J+4JRPcn1cs9j8GMlFHnBLHgGIFtAbUl+8vKbqwd1P2hjYUu8ou6yye1KaJ9e9ZHDV/QudKRKdeA8P3n4hW8ciOH/NncPLfydT++b81gsm+EHgidkTfkS5k7bv1HWEsbzUnFGcAqlKBDkxDayOhnuCl8CjGGlI8Iu43Ebja8rR1fOGfaP7t+f4jcCAwEAAaOB4TCB3jAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL2VlLXJvb3QtY2EuY3JsME8GCCsGAQUFBwEBBEMwQTA/BggrBgEFBQcwAoYzaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3J0L2VlLXJvb3QtY2EuY3J0MB0GA1UdDgQWBBQ254Y1XrboT46RFULk5+Q/XdQXwzANBgkqhkiG9w0BAQsFAAOCAQEANK7zGuqVACRV4ZJWOqvpbgNs7ESGHd8SVOGaZIpPXb2mCIYthliE+hwS23iGk4QA6IXluYTsSf9q3BYxJBCWnslsriV3vCgFAtWNLL1nii+KGIZC+RetOy5ABSPpH0EHJukmBLdv2gHjZjjiOqvKmxoh+OXrvXHuA8YgrjWDdBplYLR1dgYttcx7PQBEVl7Xf4+nB8Y1JGjboD5q0Zz8vN49qHZG/VuCtfgupFYNWVRO8BLYeFzgH8Ge6VzRkLHG3cQ9jGM6tU7U7ff7OEkoUbW36gnByr2vN3xPTIiy+TojAAM6DvK4FfanDOFZf4cVWjCMXNs2wB6wJCUaXvM2UA=="));
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
