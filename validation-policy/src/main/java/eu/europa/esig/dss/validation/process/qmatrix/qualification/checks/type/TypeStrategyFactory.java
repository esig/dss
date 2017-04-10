package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type;

import java.util.List;

import eu.europa.esig.dss.validation.process.qmatrix.EIDASUtils;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.cert.TypeByCertificatePostEIDAS;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.cert.TypeByCertificatePreEIDAS;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.tl.TypeByTL;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public final class TypeStrategyFactory {

	private TypeStrategyFactory() {
	}

	public static TypeStrategy createTypeFromCert(CertificateWrapper signingCertificate) {
		if (EIDASUtils.isPostEIDAS(signingCertificate.getNotBefore())) {
			return new TypeByCertificatePostEIDAS(signingCertificate);
		} else {
			return new TypeByCertificatePreEIDAS(signingCertificate);
		}
	}

	public static TypeStrategy createTypeFromTL(List<TrustedServiceWrapper> trustedServices, TypeStrategy typeInCert) {
		return new TypeByTL(trustedServices, typeInCert);
	}

}
