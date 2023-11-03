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
import eu.europa.esig.dss.enumerations.ServiceQualification;

import java.util.Collections;
import java.util.List;

/**
 * Verifies whether the applicable qualifiers are known and can be processed by the application
 *
 */
public class TrustServiceQualifiersKnownConsistency implements TrustServiceCondition {

    /**
     * Default constructor
     */
    public TrustServiceQualifiersKnownConsistency() {
        // empty
    }

    @Override
    public boolean isConsistent(TrustServiceWrapper trustService) {
        List<String> capturedQualifiers = trustService.getCapturedQualifierUris();
        for (String qualifier : capturedQualifiers) {
            if (!isQualifierKnown(qualifier)) {
                return false;
            }
        }
        return true;
    }

    public boolean isQualifierKnown(String qualifierUri) {
        List<String> singletonList = Collections.singletonList(qualifierUri);
        return ServiceQualification.isQcWithSSCD(singletonList) || ServiceQualification.isQcNoSSCD(singletonList) ||
                ServiceQualification.isQcSSCDStatusAsInCert(singletonList) || ServiceQualification.isQcWithQSCD(singletonList) ||
                ServiceQualification.isQcNoQSCD(singletonList) || ServiceQualification.isQcQSCDStatusAsInCert(singletonList) ||
                ServiceQualification.isQcQSCDManagedOnBehalf(singletonList) || ServiceQualification.isQcForLegalPerson(singletonList) ||
                ServiceQualification.isQcForEsig(singletonList) || ServiceQualification.isQcForEseal(singletonList) ||
                ServiceQualification.isQcForWSA(singletonList) || ServiceQualification.isNotQualified(singletonList) ||
                ServiceQualification.isQcStatement(singletonList);
    }

}
