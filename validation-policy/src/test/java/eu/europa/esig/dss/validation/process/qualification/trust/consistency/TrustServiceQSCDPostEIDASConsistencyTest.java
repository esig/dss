package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TrustServiceQSCDPostEIDASConsistencyTest extends AbstractTrustServiceConsistencyTest {

    private TrustServiceCondition condition = new TrustServiceQSCDPostEIDASConsistency();

    @Test
    public void postEidasQscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void postEidasNoQscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void postEidasSscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri()));
        assertFalse(condition.isConsistent(service));
    }

    @Test
    public void postEidasNoSscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri()));
        assertFalse(condition.isConsistent(service));
    }

    @Test
    public void postEidasQscdCombinationTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri(), ServiceQualification.QC_WITH_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void postEidasNoQscdCombinationTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(POST_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri(), ServiceQualification.QC_NO_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void preEidasQscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void preEidasNoQscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void preEidasSscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void preEidasNoSscdTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void preEidasQscdCombinationTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri(), ServiceQualification.QC_WITH_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void preEidasNoQscdCombinationTest() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setStartDate(PRE_EIDAS_DATE);
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri(), ServiceQualification.QC_NO_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

}
