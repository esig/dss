package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.tl;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.ServiceQualification;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.AbstractQualificationCondition;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class QualificationByTL extends AbstractQualificationCondition {

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
