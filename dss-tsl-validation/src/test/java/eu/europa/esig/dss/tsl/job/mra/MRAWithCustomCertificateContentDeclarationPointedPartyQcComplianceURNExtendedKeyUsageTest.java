package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.ExtendedKeyUsageCondition;
import eu.europa.esig.trustedlist.enums.Assert;

import java.util.Collections;

public class MRAWithCustomCertificateContentDeclarationPointedPartyQcComplianceURNExtendedKeyUsageTest extends AbstractMRALOTLTest {

    @Override
    protected Assert getCertificateContentDeclarationPointedPartyQcComplianceAssertStatus() {
        return Assert.ALL;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointedPartyQcCompliance() {
        return new ExtendedKeyUsageCondition(Collections.singletonList("urn:oid:" + ExtendedKeyUsage.TIMESTAMPING.getOid()));
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