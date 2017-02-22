package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.tl;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.ServiceQualification;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.AbstractQSCDCondition;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class QSCDByTL extends AbstractQSCDCondition {

	private final List<TrustedServiceWrapper> trustedServices;
	private final Condition qualified;
	private final Condition qscdFromCertificate;

	public QSCDByTL(List<TrustedServiceWrapper> trustedServices, Condition qualified, Condition qscdFromCertificate) {
		this.trustedServices = trustedServices;
		this.qualified = qualified;
		this.qscdFromCertificate = qscdFromCertificate;
	}

	@Override
	public boolean check() {
		if (Utils.isCollectionEmpty(trustedServices) || !qualified.check()) {
			return false;
		} else {
			for (TrustedServiceWrapper trustedService : trustedServices) {
				List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

				// If overrules
				if (Utils.isCollectionNotEmpty(capturedQualifiers)) {

					if (ServiceQualification.isQcNoQSCD(capturedQualifiers)) {
						return false;
					}

					if (ServiceQualification.isQcWithQSCD(capturedQualifiers) || ServiceQualification.isQcQSCDManagedOnBehalf(capturedQualifiers)) {
						return true;
					}

				}
			}

			return qscdFromCertificate.check();
		}
	}

}
