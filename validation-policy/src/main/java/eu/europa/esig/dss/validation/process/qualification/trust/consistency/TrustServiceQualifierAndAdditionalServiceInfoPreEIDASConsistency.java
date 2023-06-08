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
package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.AdditionalServiceInformation;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;

import java.util.Date;
import java.util.List;

/**
 * Verifies whether type qualifiers and additional service information are consistent for pre-eIDAS trusted service
 *
 */
public class TrustServiceQualifierAndAdditionalServiceInfoPreEIDASConsistency implements TrustServiceCondition {

    /**
     * Default constructor
     */
    public TrustServiceQualifierAndAdditionalServiceInfoPreEIDASConsistency() {
        // empty
    }

    @Override
    public boolean isConsistent(TrustServiceWrapper trustService) {
        Date startDate = trustService.getStartDate();
        if (EIDASUtils.isPreEIDAS(startDate)) {

            List<String> asis = trustService.getAdditionalServiceInfos();
            if (AdditionalServiceInformation.isForeSealsOnly(asis) || AdditionalServiceInformation.isForWebAuthOnly(asis)) {
                return false;
            }

            List<String> qualifiers = trustService.getCapturedQualifiers();
            if (ServiceQualification.isQcForEseal(qualifiers) || ServiceQualification.isQcForWSA(qualifiers)) {
                return false;
            }

        }
        return true;
    }

}
