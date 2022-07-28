package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ServiceByMRAEnactedFilterTest {

    @Test
    public void noTSTest() {
        ServiceByMRAEnactedFilter filter = new ServiceByMRAEnactedFilter();
        assertTrue(Utils.isCollectionEmpty(filter.filter(new ArrayList<>())));
    }

    @Test
    public void enactedTest() {
        ServiceByMRAEnactedFilter filter = new ServiceByMRAEnactedFilter();

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setEnactedMRA(true);

        assertEquals(1, filter.filter(Collections.singletonList(service)).size());
    }

    @Test
    public void notEnactedTest() {
        ServiceByMRAEnactedFilter filter = new ServiceByMRAEnactedFilter();

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setEnactedMRA(false);

        assertEquals(0, filter.filter(Collections.singletonList(service)).size());
    }

    @Test
    public void noEnactedTest() {
        ServiceByMRAEnactedFilter filter = new ServiceByMRAEnactedFilter();

        TrustedServiceWrapper service = new TrustedServiceWrapper();
        service.setEnactedMRA(null);

        assertEquals(0, filter.filter(Collections.singletonList(service)).size());
    }

}
