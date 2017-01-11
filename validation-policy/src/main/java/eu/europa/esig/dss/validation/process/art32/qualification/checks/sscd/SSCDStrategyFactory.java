package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd;

import eu.europa.esig.dss.validation.process.art32.EIDASConstants;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.cert.SSCDByCertificatePostEIDAS;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.cert.SSCDByCertificatePreEIDAS;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.tl.SSCDByTL;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public final class SSCDStrategyFactory {

	private SSCDStrategyFactory() {
	}

	public static SSCDStrategy createSSCDFromCert(CertificateWrapper signingCertificate) {
		if (EIDASConstants.EIDAS_DATE.before(signingCertificate.getNotBefore())) {
			return new SSCDByCertificatePreEIDAS(signingCertificate);
		} else {
			return new SSCDByCertificatePostEIDAS(signingCertificate);
		}
	}

	public static SSCDStrategy createSSCDFromTL(TrustedServiceWrapper trustedService, QualifiedStatus qualifiedStatus, SSCDStatus sscdFromCertificate) {
		return new SSCDByTL(trustedService, qualifiedStatus, sscdFromCertificate);
	}

}
