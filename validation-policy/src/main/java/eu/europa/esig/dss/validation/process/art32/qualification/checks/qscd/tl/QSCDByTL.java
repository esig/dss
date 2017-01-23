package eu.europa.esig.dss.validation.process.art32.qualification.checks.qscd.tl;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qscd.AbstractQSCDCondition;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class QSCDByTL extends AbstractQSCDCondition {

	private final TrustedServiceWrapper trustedService;
	private final Condition qualified;
	private final Condition qscdFromCertificate;

	public QSCDByTL(TrustedServiceWrapper trustedService, Condition qualified, Condition qscdFromCertificate) {
		this.trustedService = trustedService;
		this.qualified = qualified;
		this.qscdFromCertificate = qscdFromCertificate;
	}

	@Override
	public boolean check() {
		if (trustedService == null || !qualified.check()) {
			return false;
		} else {
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

			return qscdFromCertificate.check();
		}
	}

}
