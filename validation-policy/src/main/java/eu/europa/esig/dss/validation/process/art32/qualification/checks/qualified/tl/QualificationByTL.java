package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.tl;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.CertificateCondition;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class QualificationByTL implements QualificationStrategy {

	private final TrustedServiceWrapper trustedService;
	private final CertificateWrapper signingCertificate;
	private final QualifiedStatus qualifiedStatusFromCert;

	public QualificationByTL(TrustedServiceWrapper trustedService, CertificateWrapper signingCertificate, QualifiedStatus qualifiedStatusFromCert) {
		this.trustedService = trustedService;
		this.signingCertificate = signingCertificate;
		this.qualifiedStatusFromCert = qualifiedStatusFromCert;
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {
		if (trustedService == null) {
			return QualifiedStatus.NOT_QC;
		} else {
			List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

			// If overrules
			if (Utils.isCollectionNotEmpty(capturedQualifiers)) {

				CertificateCondition isQCTypeESign = new CertificateWithQCTypeESignCondition();

				if (ServiceQualification.isNotQualified(capturedQualifiers)) {
					return QualifiedStatus.NOT_QC;
				} else if (ServiceQualification.isQcForLegalPerson(capturedQualifiers) || ServiceQualification.isQcForEseal(capturedQualifiers)
						|| ServiceQualification.isQcForWSA(capturedQualifiers)) {
					return QualifiedStatus.QC_NOT_FOR_ESIGN;
				} else if (ServiceQualification.isQcStatement(capturedQualifiers) && ServiceQualification.isQcForEsig(capturedQualifiers)) {
					return QualifiedStatus.QC_FOR_ESIGN;
				} else if (ServiceQualification.isQcStatement(capturedQualifiers) && isQCTypeESign.check(signingCertificate)) {
					return QualifiedStatus.QC_FOR_ESIGN;
				} else {
					return qualifiedStatusFromCert;
				}

			} else {
				return qualifiedStatusFromCert;
			}
		}
	}

}
