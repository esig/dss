package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustedServiceChecker;

import java.util.ArrayList;
import java.util.List;

/**
 * Filters TrustedServices by QSCD consistency
 *
 */
public class ConsistentServiceByQSCDFilter implements TrustedServiceFilter {

    @Override
    public List<TrustedServiceWrapper> filter(List<TrustedServiceWrapper> trustedServices) {
        List<TrustedServiceWrapper> result = new ArrayList<>();
        for (TrustedServiceWrapper service : trustedServices) {
            if (TrustedServiceChecker.isQSCDConsistent(service) &&
                    TrustedServiceChecker.isQSCDStatusAsInCertConsistent(service)) {
                result.add(service);
            }
        }
        return result;
    }

}
