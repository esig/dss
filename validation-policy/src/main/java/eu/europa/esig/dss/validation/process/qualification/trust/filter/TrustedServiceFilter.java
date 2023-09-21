package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;

import java.util.List;

/**
 * Used to filter acceptable Trusted Services to be used during qualification determination process
 *
 * @deprecated since DSS 5.13.
 *      Use {@code eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServiceFilter} instead
 */
@Deprecated
public interface TrustedServiceFilter {

    /**
     * Filters a list of {@code TrustServiceWrapper}s
     *
     * @param trustServices a list of {@link TrustServiceWrapper}s to filter
     * @return filtered list of {@link TrustServiceWrapper}s
     */
    @Deprecated
    List<TrustServiceWrapper> filter(List<TrustServiceWrapper> trustServices);

}