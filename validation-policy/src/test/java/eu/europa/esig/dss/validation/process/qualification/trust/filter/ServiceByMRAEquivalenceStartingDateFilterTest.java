package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ServiceByMRAEquivalenceStartingDateFilterTest {

    private final static Date DATE1 = DatatypeConverter.parseDateTime("2015-07-01T00:00:00-00:00").getTime();
    private final static Date DATE2 = DatatypeConverter.parseDateTime("2016-07-01T00:00:00-00:00").getTime();
    private final static Date DATE3 = DatatypeConverter.parseDateTime("2017-07-01T00:00:00-00:00").getTime();

    @Test
    public void noTSTest() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE2);
        assertTrue(Utils.isCollectionEmpty(filter.filter(new ArrayList<>())));
    }

    @Test
    public void testValid() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE2);

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE1);

        assertTrue(filter.isAcceptable(service));
    }

    @Test
    public void testInvalid() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE2);

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE3);

        assertFalse(filter.isAcceptable(service));
    }

    @Test
    public void testSameTime() {
        ServiceByMRAEquivalenceStartingDateFilter filter = new ServiceByMRAEquivalenceStartingDateFilter(DATE1);

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE1);

        assertTrue(filter.isAcceptable(service));
    }

    @Test
    public void testNoDate() {
        ServiceByDateFilter filter = new ServiceByDateFilter(null);

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setMraTrustServiceEquivalenceStatusStartingTime(DATE1);

        assertFalse(filter.isAcceptable(service));
    }

    @Test
    public void testNoStartingDate() {
        ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

        TrustedServiceWrapper service = new TrustedServiceWrapper();

        assertFalse(filter.isAcceptable(service));
    }

}
