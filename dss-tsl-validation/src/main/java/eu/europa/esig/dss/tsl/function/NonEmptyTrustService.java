package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServicesListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;

public class NonEmptyTrustService implements TrustServiceProviderPredicate {

	@Override
	public boolean test(TSPType t) {
		TSPServicesListType servicesList = t.getTSPServices();
		return (servicesList != null && Utils.isCollectionNotEmpty(servicesList.getTSPService()));
	}

}
