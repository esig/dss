package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustedServiceStatus;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class GrantedServiceFilter extends AbstractTrustedServiceFilter {

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		if (EIDASUtils.isPostEIDAS(service.getStartDate())) {
			return TrustedServiceStatus.isAcceptableStatusAfterEIDAS(service.getStatus());
		} else {
			return TrustedServiceStatus.isAcceptableStatusBeforeEIDAS(service.getStatus());
		}
	}

}
