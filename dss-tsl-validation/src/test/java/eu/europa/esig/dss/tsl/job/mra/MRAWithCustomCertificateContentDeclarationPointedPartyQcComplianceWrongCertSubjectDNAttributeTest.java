package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.spi.tsl.Condition;
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
