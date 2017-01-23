package eu.europa.esig.dss.validation.process.art32.qualification.checks.type.tl;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.type.Type;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class TypeByTL implements TypeStrategy {

	private final TrustedServiceWrapper trustedService;
	private final TypeStrategy typeInCert;

	public TypeByTL(TrustedServiceWrapper trustedService, TypeStrategy typeInCert) {
		this.trustedService = trustedService;
		this.typeInCert = typeInCert;
	}

	@Override
	public Type getType() {
		if (trustedService != null) {

			List<String> usageQualifiers = ServiceQualification.getUsageQualifiers(trustedService.getCapturedQualifiers());

			// If overrules
			if (Utils.isCollectionNotEmpty(usageQualifiers)) {

				if (ServiceQualification.isQcForEsig(usageQualifiers)) {
					return Type.ESIGN;
				}

				if (ServiceQualification.isQcForEseal(usageQualifiers) || ServiceQualification.isQcForWSA(usageQualifiers)) {
					return Type.ESEAL;
				}

			}

		}
		return typeInCert.getType();
	}

}
