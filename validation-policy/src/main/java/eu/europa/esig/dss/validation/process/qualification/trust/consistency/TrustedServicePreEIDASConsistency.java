package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.process.qualification.trust.AdditionalServiceInformation;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

/**
 * For Seals or Web Authentication are only allowed after eIDAS
 */
class TrustedServicePreEIDASConsistency implements TrustedServiceCondition {

	@Override
	public boolean isConsistent(TrustedServiceWrapper trustedService) {

		Date startDate = trustedService.getStartDate();
		if (EIDASUtils.isPreEIDAS(startDate)) {
			List<String> asis = trustedService.getAdditionalServiceInfos();
			if (AdditionalServiceInformation.isForeSealsOnly(asis) || AdditionalServiceInformation.isForWebAuthOnly(asis)) {
				return false;
			}

			List<String> qualifiers = trustedService.getCapturedQualifiers();
			if (ServiceQualification.isQcForEseal(qualifiers) || ServiceQualification.isQcForWSA(qualifiers)) {
				return false;
			}
		}

		return true;
	}

}
