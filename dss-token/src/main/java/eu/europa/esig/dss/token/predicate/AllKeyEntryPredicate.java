package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

/**
 * This predicate is used as a default implementation and accepts all keys.
 *
 */
public class AllKeyEntryPredicate implements DSSKeyEntryPredicate {

    /**
     * Default constructor
     */
    public AllKeyEntryPredicate() {
        // empty
    }

    @Override
    public boolean test(DSSPrivateKeyEntry dssPrivateKeyEntry) {
        // accept every key
        return true;
    }

}
