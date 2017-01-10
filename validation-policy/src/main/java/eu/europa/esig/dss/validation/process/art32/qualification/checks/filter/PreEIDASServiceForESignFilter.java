package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.policy.TrustedServiceStatus;

public class PreEIDASServiceForESignFilter extends AbstractTrustedServiceFilter {

	@Override
	List<XmlTrustedService> getAcceptableServices(List<XmlTrustedService> originServices) {
		List<XmlTrustedService> result = new ArrayList<XmlTrustedService>();
		for (XmlTrustedService service : originServices) {
			if (isCaQc(service) && hasAcceptableStatus(service)) {
				result.add(service);
			}
		}
		return result;
	}

	private boolean isCaQc(XmlTrustedService service) {
		return ServiceQualification.isCaQc(service.getServiceType());
	}

	private boolean hasAcceptableStatus(XmlTrustedService service) {
		return TrustedServiceStatus.isAcceptableStatusBeforeEIDAS(service.getStatus());
	}

}
