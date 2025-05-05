package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.policy.crypto.xml.jaxb.SecuritySuitabilityPolicyType;
import jakarta.xml.bind.UnmarshalException;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CryptographicSuiteXmlFacadeTest {

    @Test
    void test() throws Exception {
        SecuritySuitabilityPolicyType securitySuitabilityPolicy = CryptographicSuiteXmlFacade.newFacade()
                .unmarshall(new File("src/test/resources/19312MachineReadable-fix.xml"));
        assertNotNull(securitySuitabilityPolicy);

        String marshall = CryptographicSuiteXmlFacade.newFacade().marshall(securitySuitabilityPolicy);
        assertNotNull(marshall);

        SecuritySuitabilityPolicyType scp = CryptographicSuiteXmlFacade.newFacade().unmarshall(marshall);
        assertNotNull(scp);
    }

    @Test
    void testFailure() throws Exception {
        // TODO : the original XML schema fails XSD validation
        File constraintsFile = new File("src/test/resources/19312MachineReadable.xml");
        assertThrows(UnmarshalException.class, () -> CryptographicSuiteXmlFacade.newFacade().unmarshall(constraintsFile));
    }

}
