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
import eu.europa.esig.dss.tsl.dto.condition.CertSubjectDNAttributeCondition;
import eu.europa.esig.trustedlist.enums.Assert;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.util.Arrays;

public class MRAWithCustomCertificateContentDeclarationPointedPartyQcComplianceWrongCertSubjectDNAttributeTest extends AbstractMRALOTLTest {

    @Override
    protected Assert getCertificateContentDeclarationPointedPartyQcComplianceAssertStatus() {
        return Assert.ALL;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointedPartyQcCompliance() {
        return new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.C.getId(), BCStyle.DATE_OF_BIRTH.getId()));
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
