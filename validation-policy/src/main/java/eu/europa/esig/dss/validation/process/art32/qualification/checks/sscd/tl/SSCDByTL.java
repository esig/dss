package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.tl;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.art32.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.Condition;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.AbstractSSCDCondition;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class SSCDByTL extends AbstractSSCDCondition {

	private final TrustedServiceWrapper trustedService;
	private final Condition qualified;
	private final Condition sscdFromCertificate;

	public SSCDByTL(TrustedServiceWrapper trustedService, Condition qualified, Condition sscdFromCertificate) {
		this.trustedService = trustedService;
		this.qualified = qualified;
		this.sscdFromCertificate = sscdFromCertificate;
	}

	@Override
	public boolean check() {
		if (trustedService == null || !qualified.check()) {
			return false;
		} else {
			List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

			// If overrules
			if (Utils.isCollectionNotEmpty(capturedQualifiers)) {

				if (ServiceQualification.isQcNoSSCD(capturedQualifiers)) {
					return false;
				}

				if (ServiceQualification.isQcWithSSCD(capturedQualifiers) || ServiceQualification.isQcSscdManagedOnBehalf(capturedQualifiers)) {
					return true;
				}

			}

			return sscdFromCertificate.check();
		}
	}

}
