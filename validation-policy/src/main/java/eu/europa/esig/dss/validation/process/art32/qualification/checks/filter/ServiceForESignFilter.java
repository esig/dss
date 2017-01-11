package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import eu.europa.esig.dss.validation.process.art32.AdditionalServiceInformation;
import eu.europa.esig.dss.validation.process.art32.EIDASUtils;
import eu.europa.esig.dss.validation.process.art32.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.TrustedServiceStatus;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class ServiceForESignFilter extends AbstractTrustedServiceFilter {

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		if (EIDASUtils.isPostEIDAS(service.getStartDate())) {
			return isCaQc(service) && hasAcceptableStatusAfterEIDAS(service) && hasAdditionnalServiceInfoForEsign(service);
		} else {
			return isCaQc(service) && hasAcceptableStatusBeforeEIDAS(service);
		}
	}

	private boolean isCaQc(TrustedServiceWrapper service) {
		return ServiceQualification.isCaQc(service.getType());
	}

	private boolean hasAcceptableStatusAfterEIDAS(TrustedServiceWrapper service) {
		return TrustedServiceStatus.isAcceptableStatusAfterEIDAS(service.getStatus());
	}

	private boolean hasAcceptableStatusBeforeEIDAS(TrustedServiceWrapper service) {
		return TrustedServiceStatus.isAcceptableStatusBeforeEIDAS(service.getStatus());
	}

	private boolean hasAdditionnalServiceInfoForEsign(TrustedServiceWrapper service) {
		return AdditionalServiceInformation.isForeSignatures(service.getAdditionalServiceInfos());
	}

}
