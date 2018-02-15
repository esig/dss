package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class CaQcServiceFilter extends AbstractTrustedServiceFilter {

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		return ServiceQualification.isCaQc(service.getType());
	}

}
