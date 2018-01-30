package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.certificate.QSCDStatus;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

class QSCDByTL implements QSCDStrategy {

	private final List<TrustedServiceWrapper> trustedServices;
	private final QualifiedStatus qualified;
	private final QSCDStrategy qscdFromCertificate;

	public QSCDByTL(List<TrustedServiceWrapper> trustedServices, QualifiedStatus qualified, QSCDStrategy qscdFromCertificate) {
		this.trustedServices = trustedServices;
		this.qualified = qualified;
		this.qscdFromCertificate = qscdFromCertificate;
	}

	@Override
	public QSCDStatus getQSCDStatus() {
		if (Utils.isCollectionEmpty(trustedServices) || !QualifiedStatus.isQC(qualified)) {
			return QSCDStatus.NOT_QSCD;
		} else {
			for (TrustedServiceWrapper trustedService : trustedServices) {
				List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

				// If overrules
				if (Utils.isCollectionNotEmpty(capturedQualifiers)) {

					if (ServiceQualification.isQcNoQSCD(capturedQualifiers)) {
						return QSCDStatus.NOT_QSCD;
					}

					if (ServiceQualification.isQcWithQSCD(capturedQualifiers) || ServiceQualification.isQcQSCDManagedOnBehalf(capturedQualifiers)) {
						return QSCDStatus.QSCD;
					}

				}
			}

			return qscdFromCertificate.getQSCDStatus();
		}
	}

}
