package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.tl;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.art32.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.AbstractQualificationCondition;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class QualificationByTL extends AbstractQualificationCondition {

	private final TrustedServiceWrapper trustedService;
	private final CertificateWrapper signingCertificate;
	private final QualificationStrategy qualifiedInCert;

	public QualificationByTL(TrustedServiceWrapper trustedService, CertificateWrapper signingCertificate, QualificationStrategy qualifiedInCert) {
		this.trustedService = trustedService;
		this.signingCertificate = signingCertificate;
		this.qualifiedInCert = qualifiedInCert;
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {
		if (trustedService == null) {
			return QualifiedStatus.NOT_QC;
		} else {
			List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

			// If overrules
			if (Utils.isCollectionNotEmpty(capturedQualifiers)) {

				if (ServiceQualification.isNotQualified(capturedQualifiers)) {
					return QualifiedStatus.NOT_QC;
				}

				if (ServiceQualification.isQcForLegalPerson(capturedQualifiers) || ServiceQualification.isQcForEseal(capturedQualifiers)
						|| ServiceQualification.isQcForWSA(capturedQualifiers)) {
					return QualifiedStatus.QC_NOT_FOR_ESIGN;
				}

				if (ServiceQualification.isQcStatement(capturedQualifiers) && ServiceQualification.isQcForEsig(capturedQualifiers)) {
					return QualifiedStatus.QC_FOR_ESIGN;
				}

				CertificateWithQCTypeESignCondition isQCTypeESign = new CertificateWithQCTypeESignCondition(signingCertificate);
				if (ServiceQualification.isQcStatement(capturedQualifiers) && isQCTypeESign.check()) {
					return QualifiedStatus.QC_FOR_ESIGN;
				}

			}
			return qualifiedInCert.getQualifiedStatus();
		}
	}

}
