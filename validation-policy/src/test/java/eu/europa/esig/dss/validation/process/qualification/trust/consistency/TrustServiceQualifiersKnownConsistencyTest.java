package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TrustServiceQualifiersKnownConsistencyTest extends AbstractTrustServiceConsistencyTest {

    private final static TrustServiceCondition condition = new TrustServiceQualifiersKnownConsistency();

    @Test
    public void testQCWithSSCD() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_SSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCNoSSCD() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_SSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCSSCDStatusAsInCert() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_SSCD_STATUS_AS_IN_CERT.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCWithQSCD() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCNoQSCD() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_QSCD.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCQSCDStatusAsInCert() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_QSCD_STATUS_AS_IN_CERT.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCQSCDManagedOnBehalf() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCForLegalPerson() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_FOR_LEGAL_PERSON.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCForESig() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_FOR_ESIG.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCForESeal() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_FOR_ESEAL.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCForWSA() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_FOR_WSA.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testNotQualified() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.NOT_QUALIFIED.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testQCStatement() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_STATEMENT.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testKnownQualifierCombination() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri(), ServiceQualification.QC_FOR_ESIG.getUri()));
        assertTrue(condition.isConsistent(service));
    }

    @Test
    public void testNotKnownQualifier() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList("custom-uri"));
        assertFalse(condition.isConsistent(service));
    }

    @Test
    public void testNotKnownQualifierCombination() {
        TrustServiceWrapper service = new TrustServiceWrapper();
        service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri(), "custom-uri"));
        assertFalse(condition.isConsistent(service));
    }

}
