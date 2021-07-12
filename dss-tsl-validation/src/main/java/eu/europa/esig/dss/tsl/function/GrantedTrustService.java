/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustedServiceStatus;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;

/**
 * Filters TrustServices by 'granted' property (supports pre- and post- eIDAS)
 *
 */
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