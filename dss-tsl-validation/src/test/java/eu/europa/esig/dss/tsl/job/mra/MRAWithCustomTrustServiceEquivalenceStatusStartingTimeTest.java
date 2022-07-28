package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;

public class MRAWithCustomTrustServiceEquivalenceStatusStartingTimeTest extends AbstractMRALOTLTest {

    private Date startingTime;

    @BeforeEach
    public void initTime() {
        startingTime = new Date();
    }

    @Override
    protected Date getTrustServiceEquivalenceStatusStartingTime() {
        return startingTime;
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
        return null;
    }

}
