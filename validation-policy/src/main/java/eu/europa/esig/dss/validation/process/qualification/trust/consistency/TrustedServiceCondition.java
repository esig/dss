package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;

/**
 * Checks whether the TrustService is valid
 *
 * @deprecated since DSS 5.13.
 *      Use {@code eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustServiceCondition} instead
 */
@Deprecated
public interface TrustedServiceCondition {

    /**
     * Whether the TrustService is consistent
     *
     * @param trustService {@link TrustServiceWrapper} to check
     * @return TRUE if the {@code trustService} is consistent, FALSE otherwise
     */
    @Deprecated
    boolean isConsistent(TrustServiceWrapper trustService);

}
