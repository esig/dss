package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.trustedlist.enums.Assert;

public class MRAWithCustomCertificateContentDeclarationPointedPartyQcTypeTest extends AbstractMRALOTLTest {

    @Override
    protected Assert getCertificateContentDeclarationPointedPartyQcTypeAssertStatus() {
        return Assert.NONE;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointedPartyQcType() {
        return new QCStatementCondition(null, "urn:oid:0.4.0.1862.1.6.2", null);
    }

    @Override
    protected Assert getCertificateContentDeclarationPointingPartyQcTypeAssertStatus() {
        return Assert.AT_LEAST_ONE;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointingPartyQcType() {
        return new QCStatementCondition(null, "urn:oid:0.4.0.1862.1.6.2", null);
    }

    @Override
    protected Indication getFinalIndication() {
        return Indication.TOTAL_PASSED;
    }

    @Override
    protected SignatureQualification getFinalSignatureQualification() {
        return SignatureQualification.QESEAL;
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
