package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;

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
			copy.setAdjunctCertSources(certificateVerifier.getAdjunctCertSources());
			copy.setTrustedCertSources(certificateVerifier.getTrustedCertSources());
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
			offlineCertificateVerifier.setAdjunctCertSources(certificateVerifier.getAdjunctCertSources());
			offlineCertificateVerifier.setTrustedCertSources(certificateVerifier.getTrustedCertSources());
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
