package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.spi.tsl.Condition;
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
