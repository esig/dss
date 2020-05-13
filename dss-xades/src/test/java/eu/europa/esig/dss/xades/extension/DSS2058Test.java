package eu.europa.esig.dss.xades.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Tag;
import org.slf4j.event.Level;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

@Tag("slow")
public class DSS2058Test extends AbstractXAdESTestValidation {
	
	private DSSDocument extendedDocument;
	
	private CommonCertificateSource adjunctCertSource;
	
	@BeforeEach
	public void init() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/OJ_C_2017_173_FULL.xml");
		
		CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
		completeCertificateVerifier.setCheckRevocationForUntrustedChains(true);
		completeCertificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert(Level.WARN));
		completeCertificateVerifier.setAlertOnRevokedCertificate(new LogOnStatusAlert(Level.ERROR));
		
		adjunctCertSource = new CommonCertificateSource();
		CertificateToken tsaCA = DSSUtils.loadCertificateFromBase64EncodedString("MIID/zCCAuegAwIBAgIQP8umE0YUpE/yhLiMgaeopDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJGUjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxKDAmBgNVBAMTH1VuaXZlcnNpZ24gVGltZXN0YW1waW5nIENBIDIwMTUwHhcNMTUwMTI5MTQwMzE1WhcNMjUwMTI5MTQwMzE1WjB3MQswCQYDVQQGEwJGUjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxKDAmBgNVBAMTH1VuaXZlcnNpZ24gVGltZXN0YW1waW5nIENBIDIwMTUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYc1VJ69W70ojewtKbCLZ+P8bDAVJ1qujzgIZEvm15GYX7Jp+Hl9rwxBdswSZ8S5A/x+0j6YMOHH0Z+iGl649+0GGX1gdAuovQKShsvLSzD/waINxkXXTVXpAW3V4dnCgcb3qaV/pO9NTk/sdRJxM8lUtWuD7TEAfLzz7Ucl6gBjDTA0Gz+AtUkNWPcofCWuDfiSDOOpyKwSxovde6SRwHdTXXIiC2Dphffjrr74MvLb0La5JAUwmJLIH42j/frgZeWk148wLMwBW+lvrIJtPz7eHNtTlNfQLrmmJHW4l+yvTsdJJDs7QYtfzBTNg1zqV8eo/hHxFTFJ8/T9wTmENJAgMBAAGjgYYwgYMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwQQYDVR0gBDowODA2BgorBgEEAftLBQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9kb2NzLnVuaXZlcnNpZ24uZXUvMB0GA1UdDgQWBBT6Te1XO70/85Ezmgs5pH9dEt0HRjANBgkqhkiG9w0BAQsFAAOCAQEAc7ud6793wgdjR8Xc1L47ufdVTamI5SHfOThtROfn8JL0HuNHKdRgv6COpdjtt6RwQEUUX/km7Q+Pn+A2gA/XoPfqD0iMfP63kMMyqgalEPRv+lXbFw3GSC9BQ9s2FL7ScvSuPm7VDZhpYN5xN6H72y4z7BgsDVNhkMu5AiWwbaWF+BHzZeiuvYHX0z/OgY2oH0hluovuRAanQd4dOa73bbZhTJPFUzkgeIzOiuYS421IiAqsjkFwu3+k4dMDqYfDKUSITbMymkRDszR0WGNzIIy2NsTBcKYCHmbIV9S+165i8YjekraBjTTSbpfbty87A1S53CzA2EN1qnmQPwqFfg==");
		adjunctCertSource.addCertificate(tsaCA);
		
		completeCertificateVerifier.setAdjunctCertSources(adjunctCertSource);
		XAdESService service = new XAdESService(completeCertificateVerifier);
		service.setTspSource(getCompositeTsa());
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		
		extendedDocument = service.extendDocument(dssDocument, signatureParameters);
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return extendedDocument;
	}
	
	@Override
	@RepeatedTest(10)
	public void validate() {
		super.validate();
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
		certificateVerifier.setAdjunctCertSources(adjunctCertSource);
		validator.setCertificateVerifier(certificateVerifier);
		return validator;
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);
		
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			if (Utils.isCollectionEmpty(certificateWrapper.getCertificateRevocationData())) {
				continue;
			}
			boolean validRevocationFound = false;
			for (CertificateRevocationWrapper certRevocationWrapper : certificateWrapper.getCertificateRevocationData()) {
				Date lastUseTime = null;
				Date poeTimeDate = null;
				for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
					for (CertificateWrapper certChainItem : timestampWrapper.getCertificateChain()) {
						if (certificateWrapper.equals(certChainItem) && (lastUseTime == null || timestampWrapper.getProductionTime().after(lastUseTime))) {
							lastUseTime = timestampWrapper.getProductionTime();
						}
					}
					List<RevocationWrapper> timestampedRevocations = timestampWrapper.getTimestampedRevocations();
					List<String> timestampedRevocationIds = timestampedRevocations.stream().map(RevocationWrapper::getId).collect(Collectors.toList());
					if (timestampedRevocationIds.contains(certRevocationWrapper.getId()) && 
							(poeTimeDate == null || timestampWrapper.getProductionTime().before(poeTimeDate))) {
						poeTimeDate = timestampWrapper.getProductionTime();
					}
				}
				assertNotNull(poeTimeDate);
				if (!validRevocationFound) {
					if (lastUseTime != null) {
						validRevocationFound = certRevocationWrapper.getProductionDate().compareTo(lastUseTime) >= 0;
					} else {
						// signature cert chain
						validRevocationFound = certRevocationWrapper.getProductionDate().compareTo(poeTimeDate) <= 0;
					}
				}
			}
			assertTrue(validRevocationFound, "Failed for certificate : " + certificateWrapper.getId());
		}
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(1, diagnosticData.getAllOrphanRevocationObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}

}
