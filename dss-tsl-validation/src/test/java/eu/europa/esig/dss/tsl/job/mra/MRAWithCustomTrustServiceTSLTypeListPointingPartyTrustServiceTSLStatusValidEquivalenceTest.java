package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;

public class MRAWithCustomTrustServiceTSLTypeListPointingPartyTrustServiceTSLStatusValidEquivalenceTest extends AbstractMRALOTLTest {

    @Override
    protected String getTrustServiceTSLTypeListPointingPartyTrustServiceTSLStatusValidEquivalence() {
        return "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";
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
