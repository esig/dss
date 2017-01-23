package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter;

import eu.europa.esig.dss.validation.process.qmatrix.EIDASUtils;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.ServiceQualification;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.TrustedServiceStatus;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class AcceptableCAQCServiceFilter extends AbstractTrustedServiceFilter {

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		if (EIDASUtils.isPostEIDAS(service.getStartDate())) {
			return isCaQc(service) && hasAcceptableStatusAfterEIDAS(service);
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

}
