package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.trustedlist.enums.Assert;

public class MRAWithCustomCertificateContentDeclarationPointedPartyQcQSCDTest extends AbstractMRALOTLTest {

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
    protected Indication getFinalIndication() {
        return Indication.TOTAL_PASSED;
    }

    @Override
    protected SignatureQualification getFinalSignatureQualification() {
        return SignatureQualification.QESIG; // overruled
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
