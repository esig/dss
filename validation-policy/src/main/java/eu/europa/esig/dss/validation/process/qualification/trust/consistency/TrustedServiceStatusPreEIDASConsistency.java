package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustedServiceStatus;

import java.util.Date;

/**
 * Verifies status of a trusted service created before eIDAS
 *
 */
public class TrustedServiceStatusPreEIDASConsistency implements TrustedServiceCondition {

    @Override
    public boolean isConsistent(TrustedServiceWrapper trustedService) {
        Date startDate = trustedService.getStartDate();
        if (EIDASUtils.isPreEIDAS(startDate)) {
            String status = trustedService.getStatus();
            return !TrustedServiceStatus.GRANTED.equals(status) && !TrustedServiceStatus.WITHDRAWN.equals(status);
        }
        return true;
    }

}
