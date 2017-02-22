package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.tl;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.ServiceQualification;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.AbstractQualificationCondition;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class QualificationByTL extends AbstractQualificationCondition {

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
