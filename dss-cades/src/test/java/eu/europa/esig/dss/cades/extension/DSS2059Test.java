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
package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.cades.signature.CAdESCounterSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

// See DSS-2060/DSS-2061
class DSS2059Test extends AbstractCAdESTestExtension {

	private DSSDocument document;
	private CAdESService service;

	@BeforeEach
	void init() {
		document = new FileDocument("src/test/resources/validation/dss2059.p7s");

		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
		certificateVerifier.setCheckRevocationForUntrustedChains(true);
		certificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert(Level.WARN));
		certificateVerifier.setAlertOnInvalidTimestamp(new LogOnStatusAlert(Level.WARN));
		certificateVerifier.setAlertOnRevokedCertificate(new LogOnStatusAlert(Level.WARN));
		certificateVerifier.setAlertOnExpiredCertificate(new LogOnStatusAlert(Level.WARN));

		certificateVerifier.setCrlSource(getCompositeCRLSource());

		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		CertificateToken tstV2CA = DSSUtils.loadCertificateFromBase64EncodedString("MIID/zCCAuegAwIBAgIQP8umE0YUpE/yhLiMgaeopDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJGUjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxKDAmBgNVBAMTH1VuaXZlcnNpZ24gVGltZXN0YW1waW5nIENBIDIwMTUwHhcNMTUwMTI5MTQwMzE1WhcNMjUwMTI5MTQwMzE1WjB3MQswCQYDVQQGEwJGUjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxKDAmBgNVBAMTH1VuaXZlcnNpZ24gVGltZXN0YW1waW5nIENBIDIwMTUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYc1VJ69W70ojewtKbCLZ+P8bDAVJ1qujzgIZEvm15GYX7Jp+Hl9rwxBdswSZ8S5A/x+0j6YMOHH0Z+iGl649+0GGX1gdAuovQKShsvLSzD/waINxkXXTVXpAW3V4dnCgcb3qaV/pO9NTk/sdRJxM8lUtWuD7TEAfLzz7Ucl6gBjDTA0Gz+AtUkNWPcofCWuDfiSDOOpyKwSxovde6SRwHdTXXIiC2Dphffjrr74MvLb0La5JAUwmJLIH42j/frgZeWk148wLMwBW+lvrIJtPz7eHNtTlNfQLrmmJHW4l+yvTsdJJDs7QYtfzBTNg1zqV8eo/hHxFTFJ8/T9wTmENJAgMBAAGjgYYwgYMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwQQYDVR0gBDowODA2BgorBgEEAftLBQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9kb2NzLnVuaXZlcnNpZ24uZXUvMB0GA1UdDgQWBBT6Te1XO70/85Ezmgs5pH9dEt0HRjANBgkqhkiG9w0BAQsFAAOCAQEAc7ud6793wgdjR8Xc1L47ufdVTamI5SHfOThtROfn8JL0HuNHKdRgv6COpdjtt6RwQEUUX/km7Q+Pn+A2gA/XoPfqD0iMfP63kMMyqgalEPRv+lXbFw3GSC9BQ9s2FL7ScvSuPm7VDZhpYN5xN6H72y4z7BgsDVNhkMu5AiWwbaWF+BHzZeiuvYHX0z/OgY2oH0hluovuRAanQd4dOa73bbZhTJPFUzkgeIzOiuYS421IiAqsjkFwu3+k4dMDqYfDKUSITbMymkRDszR0WGNzIIy2NsTBcKYCHmbIV9S+165i8YjekraBjTTSbpfbty87A1S53CzA2EN1qnmQPwqFfg==");
		commonTrustedCertificateSource.addCertificate(tstV2CA);
		certificateVerifier.setTrustedCertSources(commonTrustedCertificateSource);
		certificateVerifier.setRevocationFallback(true);
		
		service = new CAdESService(certificateVerifier);
		service.setTspSource(getUsedTSPSourceAtExtensionTime());
	}

	@Test
	@Override
	public void extendAndVerify() throws Exception {
		DSSDocument extendedDocument = extendSignature(document);
		verify(extendedDocument);
	}

	@Test
	void counterSignTest() {
		// see DSS-2178

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

		CAdESCounterSignatureParameters counterSignatureParameters = new CAdESCounterSignatureParameters();
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		counterSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		counterSignatureParameters.setSignatureIdToCounterSign(signatures.get(0).getId());

		Exception exception = assertThrows(IllegalInputException.class, () -> service.getDataToBeCounterSigned(document, counterSignatureParameters));
		assertEquals("Cannot add a counter signature to a CAdES containing an archiveTimestampV2", exception.getMessage());
	}

	@Test
	void signaturePolicyStoreTest() {
		// see DSS-2172

		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
		signaturePolicyStore.setSignaturePolicyContent(new FileDocument("src/test/resources/validation/signature-policy.der"));
		SpDocSpecification spDocSpec = new SpDocSpecification();
		spDocSpec.setId("1.2.3.4.5.6");
		signaturePolicyStore.setSpDocSpecification(spDocSpec);

		Exception exception = assertThrows(IllegalInputException.class, () -> service.addSignaturePolicyStore(document, signaturePolicyStore));
		assertEquals("Cannot add signature policy store to a CAdES containing an archiveTimestampV2", exception.getMessage());
	}

	@Override
	protected CAdESService getSignatureServiceToExtend() {
		return service;
	}

	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		// a new revocation data should be added
		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(2, certificateRevocationData.size());
		boolean revoked = false;
		for (CertificateRevocationWrapper revocationData : certificateRevocationData) {
			revoked = revoked || revocationData.isRevoked();
		}
		assertTrue(revoked);

		List<String> signatureRevocationIds = signature.foundRevocations().getRelatedRevocationData()
				.stream().map(r -> r.getId()).collect(Collectors.toList());
		signatureRevocationIds.addAll(signature.foundRevocations().getOrphanRevocationData()
				.stream().map(r -> r.getId()).collect(Collectors.toList()));

		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (ArchiveTimestampType.CAdES_V2.equals(timestampWrapper.getArchiveTimestampType())) {
				// the last ATSTv2 must be extended
				List<RelatedRevocationWrapper> timestampRevocationData = timestampWrapper.foundRevocations().getRelatedRevocationData();
				assertTrue(Utils.isCollectionNotEmpty(timestampRevocationData));
				for (RelatedRevocationWrapper revocationWrapper : timestampRevocationData) {
					assertFalse(signatureRevocationIds.contains(revocationWrapper.getId()));
				}
			}
		}
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(3, timestampList.size());

		String signatureTstId = null;
		String aTstV2Id = null;
		String aTstV3Id = null;
		for (TimestampWrapper timestampWrapper : timestampList) {
			List<String> timestampedIds = timestampWrapper.getTimestampedTimestamps().stream()
					.map(TimestampWrapper::getId).collect(Collectors.toList());

			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				signatureTstId = timestampWrapper.getId();
			} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertTrue(timestampedIds.contains(signatureTstId));
				if (ArchiveTimestampType.CAdES_V2.equals(timestampWrapper.getArchiveTimestampType())) {
					aTstV2Id = timestampWrapper.getId();
				} else if (ArchiveTimestampType.CAdES_V3.equals(timestampWrapper.getArchiveTimestampType())) {
					assertTrue(timestampedIds.contains(aTstV2Id));
					aTstV3Id = timestampWrapper.getId();
				}
			}
		}

		assertNotNull(signatureTstId);
		assertNotNull(aTstV2Id);
		assertNotNull(aTstV3Id);
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		// certificate-values shall not be present
		assertEquals(SignatureLevel.CAdES_A, diagnosticData.getFirstSignatureFormat());
	}

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_LTA;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_LTA;
	}

}
