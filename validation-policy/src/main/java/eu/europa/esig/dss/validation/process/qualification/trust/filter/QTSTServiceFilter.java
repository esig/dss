package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceTypeIdentifier;

public class QTSTServiceFilter extends AbstractTrustedServiceFilter {

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		return ServiceTypeIdentifier.isQTST(service.getType());
	}


}
