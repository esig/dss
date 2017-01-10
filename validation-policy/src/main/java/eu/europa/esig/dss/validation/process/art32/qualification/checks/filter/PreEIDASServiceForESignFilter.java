package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.policy.TrustedServiceStatus;

public class PreEIDASServiceForESignFilter extends AbstractTrustedServiceFilter {

	@Override
	boolean isAcceptable(XmlTrustedService service) {
		return isCaQc(service) && hasAcceptableStatus(service);
	}

	private boolean isCaQc(XmlTrustedService service) {
		return ServiceQualification.isCaQc(service.getServiceType());
	}

	private boolean hasAcceptableStatus(XmlTrustedService service) {
		return TrustedServiceStatus.isAcceptableStatusBeforeEIDAS(service.getStatus());
	}

}
