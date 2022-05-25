package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustedServiceChecker;

import java.util.ArrayList;
import java.util.List;

/**
 * Filters TrustedServices by status consistency
 *
 */
public class ConsistentServiceByStatusFilter implements TrustedServiceFilter {

    @Override
    public List<TrustedServiceWrapper> filter(List<TrustedServiceWrapper> trustedServices) {
        List<TrustedServiceWrapper> result = new ArrayList<>();
        for (TrustedServiceWrapper service : trustedServices) {
            if (EIDASUtils.isPostEIDAS(service.getStartDate()) || TrustedServiceChecker.isPreEIDASStatusConsistent(service)) {
                result.add(service);
            }
        }
        return result;
    }

}
