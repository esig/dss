/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
