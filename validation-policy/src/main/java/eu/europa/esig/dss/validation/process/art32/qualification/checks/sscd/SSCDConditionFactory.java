package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd;

import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.art32.EIDASUtils;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.cert.SSCDByCertificatePostEIDAS;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.cert.SSCDByCertificatePreEIDAS;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.tl.SSCDByTL;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public final class SSCDConditionFactory {

	private SSCDConditionFactory() {
	}

	public static Condition createSSCDFromCert(CertificateWrapper signingCertificate) {
		if (EIDASUtils.isPostEIDAS(signingCertificate.getNotBefore())) {
			return new SSCDByCertificatePostEIDAS(signingCertificate);
		} else {
			return new SSCDByCertificatePreEIDAS(signingCertificate);
		}
	}

	public static Condition createSSCDFromTL(TrustedServiceWrapper trustedService, Condition qualified, Condition sscdFromCertificate) {
		return new SSCDByTL(trustedService, qualified, sscdFromCertificate);
	}

}
