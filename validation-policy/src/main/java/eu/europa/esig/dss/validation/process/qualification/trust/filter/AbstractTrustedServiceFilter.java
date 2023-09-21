package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;

import java.util.ArrayList;
import java.util.List;

/**
 * Abstract filter defining the main logic of filters
 *
 * @deprecated since DSS 5.13.
 *      Use {@code eu.europa.esig.dss.validation.process.qualification.trust.filter.AbstractTrustServiceFilter} instead
 */
@Deprecated
public abstract class AbstractTrustedServiceFilter implements TrustServiceFilter {

    /**
     * Default constructor
     */
    @Deprecated
    protected AbstractTrustedServiceFilter() {
        // empty
    }

    @Override
    @Deprecated
    public List<TrustServiceWrapper> filter(List<TrustServiceWrapper> originServices) {
        List<TrustServiceWrapper> result = new ArrayList<>();
        for (TrustServiceWrapper service : originServices) {
            if (isAcceptable(service)) {
                result.add(service);
            }
        }
        return result;
    }

    /**
     * Checks whether the {@code service} is acceptable
     *
     * @param service {@link TrustServiceWrapper} to check
     * @return TRUE if the {@code service} is acceptable, FALSE otherwise
     */
    @Deprecated
    protected abstract boolean isAcceptable(TrustServiceWrapper service);

}
