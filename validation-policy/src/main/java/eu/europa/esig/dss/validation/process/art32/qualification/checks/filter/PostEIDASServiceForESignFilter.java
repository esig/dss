package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.AdditionalServiceInformation;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.policy.TrustedServiceStatus;

public class PostEIDASServiceForESignFilter extends AbstractTrustedServiceFilter {

	@Override
	boolean isAcceptable(XmlTrustedService service) {
		return isCaQc(service) && hasAcceptableStatus(service) && hasAdditionnalServiceInfoForEsign(service);
	}

	private boolean isCaQc(XmlTrustedService service) {
		return ServiceQualification.isCaQc(service.getServiceType());
	}

	private boolean hasAcceptableStatus(XmlTrustedService service) {
		return TrustedServiceStatus.isAcceptableStatusAfterEIDAS(service.getStatus());
	}

	private boolean hasAdditionnalServiceInfoForEsign(XmlTrustedService service) {
		return AdditionalServiceInformation.isForeSignatures(service.getAdditionalServiceInfoUris());
	}

}
