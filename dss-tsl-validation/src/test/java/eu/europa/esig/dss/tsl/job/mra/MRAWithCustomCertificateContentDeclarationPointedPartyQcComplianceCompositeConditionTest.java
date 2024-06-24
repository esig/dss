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
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.model.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.dto.condition.PolicyIdCondition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.trustedlist.enums.Assert;

import java.util.ArrayList;
import java.util.List;

public class MRAWithCustomCertificateContentDeclarationPointedPartyQcComplianceCompositeConditionTest extends AbstractMRALOTLTest {

    @Override
    protected Assert getCertificateContentDeclarationPointedPartyQcComplianceAssertStatus() {
        return Assert.ALL;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointedPartyQcCompliance() {
        CompositeCondition compositeCondition = new CompositeCondition(Assert.AT_LEAST_ONE);

        List<QCStatementCondition> qcStatementConditionList = new ArrayList<>();
        qcStatementConditionList.add(new QCStatementCondition("urn:oid:0.4.0.1862.1.1", null, null));
        qcStatementConditionList.add(new QCStatementCondition(null, null, "ZZ"));
        QcStatementSetCondition qcComplianceCondition = new QcStatementSetCondition(qcStatementConditionList);

        CompositeCondition notPolicyCondition = new CompositeCondition(Assert.NONE);
        notPolicyCondition.addChild(new PolicyIdCondition("urn:oid:1.3.6.1.4.1.314159.1.2"));

        compositeCondition.addChild(notPolicyCondition);
        compositeCondition.addChild(qcComplianceCondition);
        return compositeCondition;
    }

    @Override
    protected Assert getCertificateContentDeclarationPointingPartyQcComplianceAssertStatus() {
        return Assert.ALL;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointingPartyQcCompliance() {
        CompositeCondition compositeCondition = new CompositeCondition(Assert.ALL);

        CompositeCondition removeQcCClegislationCondition = new CompositeCondition(Assert.NONE);
        removeQcCClegislationCondition.addChild(new QCStatementCondition("urn:oid:0.4.0.1862.1.7", null, null));
        compositeCondition.addChild(removeQcCClegislationCondition);

        compositeCondition.addChild(new QCStatementCondition("urn:oid:0.4.0.1862.1.1", null, null));
        return compositeCondition;
    }

    @Override
    protected Indication getFinalIndication() {
        return Indication.TOTAL_PASSED;
    }

    @Override
    protected SignatureQualification getFinalSignatureQualification() {
        return SignatureQualification.QESIG;
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
