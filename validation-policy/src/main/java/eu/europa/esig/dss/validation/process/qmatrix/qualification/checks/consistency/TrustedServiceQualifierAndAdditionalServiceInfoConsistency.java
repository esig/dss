package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.consistency;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qmatrix.AdditionalServiceInformation;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class TrustedServiceQualifierAndAdditionalServiceInfoConsistency implements TrustedServiceCondition {

	private static final Map<String, String> CORRESPONDANCE_MAP_QUALIFIER_ASI;

	static {
		CORRESPONDANCE_MAP_QUALIFIER_ASI = new HashMap<String, String>();

		CORRESPONDANCE_MAP_QUALIFIER_ASI.put(ServiceQualification.QC_FOR_ESIG, AdditionalServiceInformation.FOR_ESIGNATURES);
		CORRESPONDANCE_MAP_QUALIFIER_ASI.put(ServiceQualification.QC_FOR_ESEAL, AdditionalServiceInformation.FOR_ESEALS);
		CORRESPONDANCE_MAP_QUALIFIER_ASI.put(ServiceQualification.QC_FOR_WSA, AdditionalServiceInformation.FOR_WEB_AUTHENTICATION);
	}

	public TrustedServiceQualifierAndAdditionalServiceInfoConsistency() {
	}

	@Override
	public boolean isConsistent(TrustedServiceWrapper trustedService) {

		List<String> asis = trustedService.getAdditionalServiceInfos();
		List<String> qualifiers = ServiceQualification.getUsageQualifiers(trustedService.getCapturedQualifiers());

		return isQualifierInAdditionServiceInfos(qualifiers, asis);
	}

	private boolean isQualifierInAdditionServiceInfos(List<String> qualifiers, List<String> asis) {
		if (Utils.collectionSize(asis) >= 1) {
			if (Utils.collectionSize(qualifiers) == 1) { // Cannot have more than 1 usage
				String currentUsage = qualifiers.get(0);
				String expectedASI = CORRESPONDANCE_MAP_QUALIFIER_ASI.get(currentUsage);
				return asis.contains(expectedASI);
			}
		}
		return true;
	}

}
