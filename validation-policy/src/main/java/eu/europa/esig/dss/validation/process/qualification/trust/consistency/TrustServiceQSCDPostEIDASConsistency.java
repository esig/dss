package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;

import java.util.List;

/**
 * Verifies status of a trusted service created after eIDAS
 *
 */
public class TrustServiceQSCDPostEIDASConsistency implements TrustServiceCondition {

    /**
     * Default constructor
     */
    public TrustServiceQSCDPostEIDASConsistency() {
        // empty
    }

    @Override
    public boolean isConsistent(TrustServiceWrapper trustService) {
        if (EIDASUtils.isPostEIDAS(trustService.getStartDate())) {
            List<String> capturedQualifiers = trustService.getCapturedQualifierUris();

            boolean qcPreEIDAS = ServiceQualification.isQcWithSSCD(capturedQualifiers) || ServiceQualification.isQcNoSSCD(capturedQualifiers);
            boolean qcPostEIDAS = ServiceQualification.isQcWithQSCD(capturedQualifiers) || ServiceQualification.isQcNoQSCD(capturedQualifiers);

            if (qcPreEIDAS) {
                return qcPostEIDAS;
            }
        }
        return true;
    }

}
