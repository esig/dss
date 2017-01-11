package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.tl;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.art32.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDStatus;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class SSCDByTL implements SSCDStrategy {

	private final TrustedServiceWrapper trustedService;
	private final QualifiedStatus qualifiedStatus;
	private final SSCDStatus sscdFromCertificate;

	public SSCDByTL(TrustedServiceWrapper trustedService, QualifiedStatus qualifiedStatus, SSCDStatus sscdFromCertificate) {
		this.trustedService = trustedService;
		this.qualifiedStatus = qualifiedStatus;
		this.sscdFromCertificate = sscdFromCertificate;
	}

	@Override
	public SSCDStatus getSSCDStatus() {
		if (trustedService == null || !QualifiedStatus.isQC(qualifiedStatus)) {
			return SSCDStatus.NOT_SSCD;
		} else {
			List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

			// If overrules
			if (Utils.isCollectionNotEmpty(capturedQualifiers)) {

				if (ServiceQualification.isQcNoSSCD(capturedQualifiers)) {
					return SSCDStatus.NOT_SSCD;
				}

				if (ServiceQualification.isQcWithSSCD(capturedQualifiers) || ServiceQualification.isQcSscdStatusAsInCert(capturedQualifiers)
						|| ServiceQualification.isQcSscdManagedOnBehalf(capturedQualifiers)) {
					return SSCDStatus.SSCD;
				}

			}

			return sscdFromCertificate;
		}
	}

}
