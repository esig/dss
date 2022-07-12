package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;

public class MRAWithCustomTrustServiceTSLTypeListPointedPartyServiceTypeIdentifierTest extends AbstractMRALOTLTest {

    @Override
    protected String getTrustServiceTSLTypeListPointedPartyServiceTypeIdentifier() {
        return "http://custom.country/TrstSvc/Svctype/CA/QC/for-eSig";
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
