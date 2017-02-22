package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.tl;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.ServiceQualification;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.Type;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class TypeByTL implements TypeStrategy {

	private final List<TrustedServiceWrapper> trustedServices;
	private final TypeStrategy typeInCert;

	public TypeByTL(List<TrustedServiceWrapper> trustedServices, TypeStrategy typeInCert) {
		this.trustedServices = trustedServices;
		this.typeInCert = typeInCert;
	}

	@Override
	public Type getType() {
		if (Utils.isCollectionNotEmpty(trustedServices)) {

			for (TrustedServiceWrapper trustedService : trustedServices) {
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

		}
		return typeInCert.getType();
	}

}
