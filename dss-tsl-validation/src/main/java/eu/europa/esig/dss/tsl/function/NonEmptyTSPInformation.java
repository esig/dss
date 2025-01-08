package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;

/**
 * Filters non-empty TSPInformation element
 */
public class NonEmptyTSPInformation implements TrustServiceProviderPredicate {

    /**
     * Default constructor
     */
    public NonEmptyTSPInformation() {
        // empty
    }

    @Override
    public boolean test(TSPType t) {
        return t.getTSPInformation() != null;
    }

}
