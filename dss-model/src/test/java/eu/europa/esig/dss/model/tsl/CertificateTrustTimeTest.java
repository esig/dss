package eu.europa.esig.dss.model.tsl;

import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateTrustTimeTest {

    @Test
    void isTrustedTest() {
        assertTrue(new CertificateTrustTime(true).isTrusted());
        assertFalse(new CertificateTrustTime(false).isTrusted());
        assertTrue(new CertificateTrustTime(new Date(), new Date()).isTrusted());
    }

    @Test
    void isTrustedAtTimeTest() {
        assertTrue(new CertificateTrustTime(true).isTrustedAtTime(new Date()));
        assertFalse(new CertificateTrustTime(false).isTrustedAtTime(new Date()));

        assertTrue(new CertificateTrustTime(null, null).isTrustedAtTime(new Date()));

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 2);
        Date sunsetDate = calendar.getTime();

        assertTrue(new CertificateTrustTime(startDate, null).isTrustedAtTime(new Date()));
        assertTrue(new CertificateTrustTime(null, sunsetDate).isTrustedAtTime(new Date()));
        assertTrue(new CertificateTrustTime(startDate, sunsetDate).isTrustedAtTime(new Date()));

        calendar.add(Calendar.YEAR, 3);
        Date futureDate = calendar.getTime();
        assertFalse(new CertificateTrustTime(startDate, sunsetDate).isTrustedAtTime(futureDate));
    }

    @Test
    void getJointTrustTimeTest() {
        CertificateTrustTime certificateTrustTime = new CertificateTrustTime(true);

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 2);
        Date sunsetDate = calendar.getTime();

        CertificateTrustTime jointTrustTime = certificateTrustTime.getJointTrustTime(startDate, sunsetDate);
        assertNull(jointTrustTime.getStartDate());
        assertNull(jointTrustTime.getEndDate());

        certificateTrustTime = new CertificateTrustTime(startDate, null);
        jointTrustTime = certificateTrustTime.getJointTrustTime(startDate, sunsetDate);
        assertEquals(startDate, jointTrustTime.getStartDate());
        assertNull(jointTrustTime.getEndDate());

        certificateTrustTime = new CertificateTrustTime(null, sunsetDate);
        jointTrustTime = certificateTrustTime.getJointTrustTime(startDate, sunsetDate);
        assertNull(jointTrustTime.getStartDate());
        assertEquals(sunsetDate, jointTrustTime.getEndDate());

        certificateTrustTime = new CertificateTrustTime(startDate, sunsetDate);
        jointTrustTime = certificateTrustTime.getJointTrustTime(startDate, sunsetDate);
        assertEquals(startDate, jointTrustTime.getStartDate());
        assertEquals(sunsetDate, jointTrustTime.getEndDate());

        certificateTrustTime = new CertificateTrustTime(sunsetDate, startDate);
        jointTrustTime = certificateTrustTime.getJointTrustTime(startDate, sunsetDate);
        assertEquals(startDate, jointTrustTime.getStartDate());
        assertEquals(sunsetDate, jointTrustTime.getEndDate());

        certificateTrustTime = new CertificateTrustTime(sunsetDate, startDate);
        jointTrustTime = certificateTrustTime.getJointTrustTime(startDate, sunsetDate);
        assertEquals(startDate, jointTrustTime.getStartDate());
        assertEquals(sunsetDate, jointTrustTime.getEndDate());
    }

}
