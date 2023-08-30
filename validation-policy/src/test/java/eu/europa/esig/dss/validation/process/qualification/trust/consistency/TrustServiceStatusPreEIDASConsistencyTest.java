package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustServiceStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TrustServiceStatusPreEIDASConsistencyTest extends AbstractTrustServiceConsistencyTest {

    private final static TrustServiceCondition condition = new TrustServiceStatusPreEIDASConsistency();

    @Test
    public void testAccreditedPreEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.ACCREDITED.getUri());
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testSupervisionPreEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.SUPERVISION_CEASED.getUri());
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testGrantedPreEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.GRANTED.getUri());
        assertFalse(condition.isConsistent(service));
    }

    @Test
    public void testWithdrawnPreEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.WITHDRAWN.getUri());
        assertFalse(condition.isConsistent(service));
    }

    @Test
    public void testAccreditedPostEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.ACCREDITED.getUri());
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testSupervisionPostEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.SUPERVISION_CEASED.getUri());
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testGrantedPostEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.GRANTED.getUri());
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testWithdrawnPostEidas() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setStatus(TrustServiceStatus.WITHDRAWN.getUri());
        assertTrue(condition.isConsistent(service));
    }

}
