package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;

/**
 * Filters non-empty ServiceInformation element
 */
public class NonEmptyServiceInformation implements TrustServicePredicate {

    /**
     * Default constructor
     */
    public NonEmptyServiceInformation() {
        // empty
    }

    @Override
    public boolean test(TSPServiceType tspServiceType) {
        return tspServiceType.getServiceInformation() != null &&
                tspServiceType.getServiceInformation().getStatusStartingTime() != null;
    }

}
