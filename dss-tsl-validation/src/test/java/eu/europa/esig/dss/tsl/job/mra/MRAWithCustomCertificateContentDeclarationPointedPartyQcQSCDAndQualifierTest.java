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
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.trustedlist.enums.Assert;

import java.util.HashMap;
import java.util.Map;

public class MRAWithCustomCertificateContentDeclarationPointedPartyQcQSCDAndQualifierTest extends AbstractMRALOTLTest {

    @Override
    protected Assert getCertificateContentDeclarationPointedPartyQcQSCDAssertStatus() {
        return Assert.ALL;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointedPartyQcQSCD() {
        return new QCStatementCondition("urn:oid:0.4.0.1862.1.4", null, null);
    }

    @Override
    protected Assert getCertificateContentDeclarationPointingPartyQcQSCDAssertStatus() {
        return Assert.NONE;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointingPartyQcQSCD() {
        return new QCStatementCondition("urn:oid:0.4.0.1862.1.4", null, null);
    }

    @Override
    protected Map<String, String> getQualifierEquivalenceMap() {
        Map<String, String> qualifierEquivalenceMap = new HashMap<>();
        qualifierEquivalenceMap.put("http://zz-trusted-list.go.zz/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD",
                "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD");
        return qualifierEquivalenceMap;
    }

    @Override
    protected Indication getFinalIndication() {
        return Indication.TOTAL_PASSED;
    }

    @Override
    protected SignatureQualification getFinalSignatureQualification() {
        return SignatureQualification.ADESIG_QC;
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
