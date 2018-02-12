package eu.europa.esig.dss.validation.process.qualification.certificate.checks.type;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.certificate.Type;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

class TypeByTL implements TypeStrategy {

	private final TrustedServiceWrapper trustedService;
	private final TypeStrategy typeInCert;

	public TypeByTL(TrustedServiceWrapper trustedService, TypeStrategy typeInCert) {
		this.trustedService = trustedService;
		this.typeInCert = typeInCert;
	}

	@Override
	public Type getType() {
		if (trustedService == null) {
			return Type.UNKNOWN;
		} else {

			List<String> usageQualifiers = ServiceQualification.getUsageQualifiers(trustedService.getCapturedQualifiers());

			// If overrules
			if (Utils.isCollectionNotEmpty(usageQualifiers)) {

				if (ServiceQualification.isQcForEsig(usageQualifiers)) {
					return Type.ESIGN;
				}

				if (ServiceQualification.isQcForEseal(usageQualifiers)) {
					return Type.ESEAL;
				}

				if (ServiceQualification.isQcForWSA(usageQualifiers)) {
					return Type.WSA;
				}

			}

			return typeInCert.getType();
		}
	}

}
