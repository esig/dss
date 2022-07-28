package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.trustedlist.enums.Assert;

public class MRAWithCustomCertificateContentDeclarationPointingPartyQcComplianceTest extends AbstractMRALOTLTest {

    @Override
    protected Condition getCertificateContentDeclarationPointingPartyQcCompliance() {
        CompositeCondition compositeCondition = new CompositeCondition(Assert.NONE);
        compositeCondition.addChild(new QCStatementCondition("urn:oid:0.4.0.1862.1.1", null, null));
        compositeCondition.addChild(new QCStatementCondition("urn:oid:0.4.0.1862.1.7", null, null));
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
