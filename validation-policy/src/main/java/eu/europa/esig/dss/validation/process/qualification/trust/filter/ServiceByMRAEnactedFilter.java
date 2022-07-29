package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;

import java.util.ArrayList;
import java.util.List;

/**
 * This class filters Trusted Services with MRA enacted value
 *
 */
public class ServiceByMRAEnactedFilter implements TrustedServiceFilter {

    /**
     * Default constructor
     */
    public ServiceByMRAEnactedFilter() {
    }

    @Override
    public List<TrustedServiceWrapper> filter(List<TrustedServiceWrapper> trustedServices) {
        List<TrustedServiceWrapper> result = new ArrayList<>();
        for (TrustedServiceWrapper service : trustedServices) {
            if (service.isEnactedMRA()) {
                result.add(service);
            }
        }
        return result;
    }

}
