package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

class QualificationByTL implements QualificationStrategy {

	private final List<TrustedServiceWrapper> trustedServices;
	private final QualificationStrategy qualifiedInCert;

	public QualificationByTL(List<TrustedServiceWrapper> trustedServices, QualificationStrategy qualifiedInCert) {
		this.trustedServices = trustedServices;
		this.qualifiedInCert = qualifiedInCert;
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {
		if (Utils.isCollectionEmpty(trustedServices)) {
			return QualifiedStatus.NOT_QC;
		} else {

			for (TrustedServiceWrapper trustedService : trustedServices) {
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
			}

			return qualifiedInCert.getQualifiedStatus();
		}
	}

}
