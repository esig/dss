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
package eu.europa.esig.dss.tsl.function;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

class TrustServiceProviderByTSPNameTest {

    @Test
    void test() throws Exception {
        File fileToTest = new File("src/test/resources/fr.xml");
        
        TrustStatusListType trustStatusList = TrustedListFacade.newFacade().unmarshall(fileToTest);

        
        TrustServiceProviderListType trustServiceProviderList = trustStatusList.getTrustServiceProviderList();
        List<TSPType> trustServiceProvider = trustServiceProviderList.getTrustServiceProvider();
        
        TSPType tspType = trustServiceProvider.get(0);
        
        TrustServiceProviderByTSPName selector = new TrustServiceProviderByTSPName("test");

        assertFalse(selector.test(tspType));
        
        selector = new TrustServiceProviderByTSPName("Agence Nationale des Titres Sécurisés");
        
        assertTrue(selector.test(tspType));
        
        assertFalse(selector.test(null));
        
        selector = new TrustServiceProviderByTSPName(null);
        
        assertFalse(selector.test(tspType));
        
        assertFalse(selector.test(null));
        
    }

}