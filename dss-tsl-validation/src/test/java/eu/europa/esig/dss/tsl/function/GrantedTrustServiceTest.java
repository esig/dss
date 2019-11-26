package eu.europa.esig.dss.tsl.function;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.tsl.function.GrantedTrustService;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;

class GrantedTrustServiceTest {

    @Test
    void test() throws Exception {
        TSPServiceType tspService = new TSPServiceType();
        TSPServiceInformationType informationType = new TSPServiceInformationType();
        GrantedTrustService selector = new GrantedTrustService();

        tspService.setServiceInformation(informationType);
        
        informationType.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted");
        
        assertTrue(selector.test(tspService));
        
        informationType.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision");        
        assertTrue(selector.test(tspService));

        informationType.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation");
        assertTrue(selector.test(tspService));

        informationType.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited");
        assertTrue(selector.test(tspService));

        informationType.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked");
        assertFalse(selector.test(tspService));
        
        assertFalse(selector.test(null));
        
        informationType.setServiceStatus(null);
        assertFalse(selector.test(tspService));
        
        assertFalse(selector.test(null));
        
        ServiceHistoryType serviceHistory = new ServiceHistoryType();
        tspService.setServiceHistory(serviceHistory);
        
        ServiceHistoryInstanceType historyInstance = new ServiceHistoryInstanceType();
        historyInstance.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked");
        serviceHistory.getServiceHistoryInstance().add(historyInstance);
        assertFalse(selector.test(tspService));

        historyInstance.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted");
        tspService.getServiceHistory().getServiceHistoryInstance().add(historyInstance);
        assertTrue(selector.test(tspService));
    }

}