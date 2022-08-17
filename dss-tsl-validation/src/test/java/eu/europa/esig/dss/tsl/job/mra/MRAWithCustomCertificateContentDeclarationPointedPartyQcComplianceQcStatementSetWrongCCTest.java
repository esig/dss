package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.trustedlist.enums.Assert;

import java.util.ArrayList;
import java.util.List;

public class MRAWithCustomCertificateContentDeclarationPointedPartyQcComplianceQcStatementSetWrongCCTest extends AbstractMRALOTLTest {

    @Override
    protected Assert getCertificateContentDeclarationPointedPartyQcComplianceAssertStatus() {
        return Assert.ALL;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointedPartyQcCompliance() {
        List<QCStatementCondition> qcStatementConditionList = new ArrayList<>();
        qcStatementConditionList.add(new QCStatementCondition("urn:oid:0.4.0.1862.1.1", null, null));
        qcStatementConditionList.add(new QCStatementCondition(null, null, "XX"));
        return new QcStatementSetCondition(qcStatementConditionList);
    }

    @Override
    protected Assert getCertificateContentDeclarationPointingPartyQcComplianceAssertStatus() {
        return Assert.NONE;
    }

    @Override
    protected Condition getCertificateContentDeclarationPointingPartyQcCompliance() {
        return new QCStatementCondition("urn:oid:0.4.0.1862.1.7", null, null);
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
