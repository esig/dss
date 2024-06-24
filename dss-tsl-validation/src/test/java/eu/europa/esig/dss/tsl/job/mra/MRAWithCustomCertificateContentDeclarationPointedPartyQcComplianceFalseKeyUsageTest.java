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
package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.model.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.dto.condition.KeyUsageCondition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.trustedlist.enums.Assert;

public class MRAWithCustomCertificateContentDeclarationPointedPartyQcComplianceFalseKeyUsageTest extends AbstractMRALOTLTest {

    @Override
    protected Assert getCertificateContentDeclarationPointedPartyQcComplianceAssertStatus() {
        return Assert.ALL;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointedPartyQcCompliance() {
        return new KeyUsageCondition(KeyUsageBit.NON_REPUDIATION, false);
    }

    @Override
    protected Assert getCertificateContentDeclarationPointingPartyQcComplianceAssertStatus() {
        return Assert.ALL;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointingPartyQcCompliance() {
        CompositeCondition compositeCondition = new CompositeCondition(Assert.ALL);

        CompositeCondition excludeCondition = new CompositeCondition(Assert.NONE);
        excludeCondition.addChild(new QCStatementCondition("urn:oid:0.4.0.1862.1.7", null, null));

        compositeCondition.addChild(excludeCondition);
        compositeCondition.addChild(new QCStatementCondition("urn:oid:0.4.0.1862.1.1", null, null));

        return compositeCondition;
    }

    @Override
    protected Indication getFinalIndication() {
        return Indication.TOTAL_PASSED;
    }

    @Override
    protected SignatureQualification getFinalSignatureQualification() {
        return SignatureQualification.ADESIG;
    }

    @Override
    protected boolean isEnactedMRA() {
        return true;
    }

    @Override
    protected String getMRAEnactedTrustServiceLegalIdentifier() {
        return "QCForESig";
    }

}
