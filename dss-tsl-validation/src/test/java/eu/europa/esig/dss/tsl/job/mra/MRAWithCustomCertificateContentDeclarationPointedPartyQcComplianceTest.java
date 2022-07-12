package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;

public class MRAWithCustomCertificateContentDeclarationPointedPartyQcComplianceTest extends AbstractMRALOTLTest {

    @Override
    protected Condition getCertificateContentDeclarationPointedPartyQcCompliance() {
        return new QCStatementCondition("urn:oid:0.4.0.1862.1.1", null, "TC");
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
