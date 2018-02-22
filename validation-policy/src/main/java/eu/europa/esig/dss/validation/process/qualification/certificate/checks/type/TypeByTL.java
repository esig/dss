package eu.europa.esig.dss.validation.process.qualification.certificate.checks.type;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qualification.certificate.Type;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

class TypeByTL implements TypeStrategy {

	private final TrustedServiceWrapper trustedService;
	private final QualifiedStatus qualified;
	private final TypeStrategy typeInCert;

	public TypeByTL(TrustedServiceWrapper trustedService, QualifiedStatus qualified, TypeStrategy typeInCert) {
		this.trustedService = trustedService;
		this.qualified = qualified;
		this.typeInCert = typeInCert;
	}

	@Override
	public Type getType() {

		// overrules are only applicable when the certificate is qualified (cert + TL)
		if (QualifiedStatus.isQC(qualified)) {

			if (EIDASUtils.isPreEIDAS(trustedService.getStartDate())) {
				return Type.ESIGN;
			}

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
		}

		return typeInCert.getType();
	}

}
