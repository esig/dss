package eu.europa.esig.dss.validation;

import java.util.List;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.spi.x509.CertificateSource;

public class CertificateVerifierBuilder {

	private final CertificateVerifier certificateVerifier;

	public CertificateVerifierBuilder(CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	public CertificateVerifier buildCompleteCopy() {
		CertificateVerifier copy = new CommonCertificateVerifier(true);
		if (certificateVerifier != null) {
			copy.setDefaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm());
			copy.setDataLoader(certificateVerifier.getDataLoader());
			copy.setCrlSource(certificateVerifier.getCrlSource());
			copy.setOcspSource(certificateVerifier.getOcspSource());
			copy.setCheckRevocationForUntrustedChains(certificateVerifier.isCheckRevocationForUntrustedChains());
			copy.setAdjunctCertSource(certificateVerifier.getAdjunctCertSource());
			List<CertificateSource> trustedCertSources = certificateVerifier.getTrustedCertSources();
			for (CertificateSource certificateSource : trustedCertSources) {
				copy.setTrustedCertSource(certificateSource);
			}
			copy.setAlertOnInvalidTimestamp(certificateVerifier.getAlertOnInvalidTimestamp());
			copy.setAlertOnMissingRevocationData(certificateVerifier.getAlertOnMissingRevocationData());
			copy.setAlertOnNoRevocationAfterBestSignatureTime(certificateVerifier.getAlertOnNoRevocationAfterBestSignatureTime());
			copy.setAlertOnRevokedCertificate(certificateVerifier.getAlertOnRevokedCertificate());
			copy.setAlertOnUncoveredPOE(certificateVerifier.getAlertOnUncoveredPOE());
		}
		return copy;
	}
	
	public CertificateVerifier buildOfflineAndSilentCopy() {
		CertificateVerifier offlineCertificateVerifier = new CommonCertificateVerifier(true);
		if (certificateVerifier != null) {
			offlineCertificateVerifier.setDefaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm());
			offlineCertificateVerifier.setAdjunctCertSource(certificateVerifier.getAdjunctCertSource());
			List<CertificateSource> trustedCertSources = certificateVerifier.getTrustedCertSources();
			for (CertificateSource certificateSource : trustedCertSources) {
				offlineCertificateVerifier.setTrustedCertSource(certificateSource);
			}
		}
		// disable alerting
		offlineCertificateVerifier.setAlertOnInvalidTimestamp(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnUncoveredPOE(new SilentOnStatusAlert());
		return offlineCertificateVerifier;
	}
	
}
