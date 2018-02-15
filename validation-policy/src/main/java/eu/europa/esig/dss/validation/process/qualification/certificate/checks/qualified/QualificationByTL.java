package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

class QualificationByTL implements QualificationStrategy {

	private final TrustedServiceWrapper trustedService;
	private final QualificationStrategy qualifiedInCert;

	public QualificationByTL(TrustedServiceWrapper trustedService, QualificationStrategy qualifiedInCert) {
		this.trustedService = trustedService;
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

				if (ServiceQualification.isQcStatement(capturedQualifiers)) {
					return QualifiedStatus.QC;
				}
			}

			return qualifiedInCert.getQualifiedStatus();
		}
	}

}
