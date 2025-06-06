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
package eu.europa.esig.dss.policy.crypto.json;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.CryptographicSuiteFactory;
import org.junit.jupiter.api.Test;

import java.util.Iterator;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class CryptographicSuiteJsonFactoryTest {

    @Test
    void serviceLoaderTest() {
        FileDocument cryptoSuite = new FileDocument("src/test/resources/19312MachineReadable-fix.json");

        ServiceLoader<CryptographicSuiteFactory> loader = ServiceLoader.load(CryptographicSuiteFactory.class);
        Iterator<CryptographicSuiteFactory> factoryOptions = loader.iterator();

        CryptographicSuite cryptographicSuite = null;
        while (factoryOptions.hasNext()) {
            CryptographicSuiteFactory factory = factoryOptions.next();
            if (factory.isSupported(cryptoSuite)) {
                cryptographicSuite = factory.loadCryptographicSuite(cryptoSuite);
            }
        }
        assertNotNull(cryptographicSuite);
    }

    @Test
    void serviceLoaderDefaultTest() {
        ServiceLoader<CryptographicSuiteFactory> loader = ServiceLoader.load(CryptographicSuiteFactory.class);
        Iterator<CryptographicSuiteFactory> factoryOptions = loader.iterator();

        CryptographicSuite cryptographicSuite = null;
        if (factoryOptions.hasNext()) {
            CryptographicSuiteFactory factory = factoryOptions.next();
            cryptographicSuite = factory.loadDefaultCryptographicSuite();
        }
        assertNotNull(cryptographicSuite);
    }

}
