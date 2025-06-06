/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
