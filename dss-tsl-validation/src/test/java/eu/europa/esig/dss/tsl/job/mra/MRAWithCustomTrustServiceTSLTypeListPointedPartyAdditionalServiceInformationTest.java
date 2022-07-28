package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;

public class MRAWithCustomTrustServiceTSLTypeListPointedPartyAdditionalServiceInformationTest extends AbstractMRALOTLTest {

    @Override
    protected String getTrustServiceTSLTypeListPointedPartyAdditionalServiceInformation() {
        return "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals";
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
        return false;
    }

    @Override
    protected String getMRAEnactedTrustServiceLegalIdentifier() {
        return null;
    }

}
