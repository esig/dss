package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustedServiceStatus;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;

public class GrantedTrustService implements TrustServicePredicate {

    @Override
    public boolean test(TSPServiceType trustedService) {
        if (trustedService != null) {
            TSPServiceInformationType serviceInformation = trustedService.getServiceInformation();
            
            // Current status
            if (TrustedServiceStatus.isAcceptableStatusAfterEIDAS(serviceInformation.getServiceStatus())
                    || TrustedServiceStatus.isAcceptableStatusBeforeEIDAS(serviceInformation.getServiceStatus())) {
                return true;
            }
            
            // Past
            ServiceHistoryType serviceHistory = trustedService.getServiceHistory();
            if (serviceHistory !=null && Utils.isCollectionNotEmpty(serviceHistory.getServiceHistoryInstance())) {
                for (ServiceHistoryInstanceType serviceHistoryInstance : serviceHistory.getServiceHistoryInstance()) {
                    if (TrustedServiceStatus.isAcceptableStatusAfterEIDAS(serviceHistoryInstance.getServiceStatus())
                            || TrustedServiceStatus.isAcceptableStatusBeforeEIDAS(serviceHistoryInstance.getServiceStatus())) {
                        return true;
                    }
                }
            }
            
        }
        return false;
    }

}