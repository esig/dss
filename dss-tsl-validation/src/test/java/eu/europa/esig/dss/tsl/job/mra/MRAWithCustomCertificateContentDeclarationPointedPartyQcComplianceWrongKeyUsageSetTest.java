package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.KeyUsageCondition;
import eu.europa.esig.trustedlist.enums.Assert;

import java.util.ArrayList;
import java.util.List;

public class MRAWithCustomCertificateContentDeclarationPointedPartyQcComplianceWrongKeyUsageSetTest extends AbstractMRALOTLTest {

    @Override
    protected Assert getCertificateContentDeclarationPointedPartyQcComplianceAssertStatus() {
        return Assert.ALL;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointedPartyQcCompliance() {
        List<KeyUsageCondition> keyUsageConditions = new ArrayList<>();
        keyUsageConditions.add(new KeyUsageCondition(KeyUsageBit.NON_REPUDIATION, true));
        keyUsageConditions.add(new KeyUsageCondition(KeyUsageBit.DIGITAL_SIGNATURE, true));
        keyUsageConditions.add(new KeyUsageCondition(KeyUsageBit.ENCIPHER_ONLY, false));
        return new KeyUsageSetCondition(keyUsageConditions);
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
