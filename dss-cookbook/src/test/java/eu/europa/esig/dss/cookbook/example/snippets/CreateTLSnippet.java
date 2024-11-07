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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.ObjectFactory;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CreateTLSnippet {

    @Test
    void createTrustedList() throws Exception {
        // tag::demoSign[]
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.trustedlist.jaxb.tsl.ObjectFactory;
        // import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
        // import eu.europa.esig.trustedlist.TrustedListFacade;
        // import java.io.ByteArrayOutputStream;

        // The object factory to use
        ObjectFactory objectFactory = new ObjectFactory();
        // Create an empty 'TrustServiceStatusList' element
        TrustStatusListType trustStatusListType = objectFactory.createTrustStatusListType();

        // Fill the requred information, Id, ...
        trustStatusListType.setId("Demo-TL");

        // Store to file
        DSSDocument modifiedUnsignedTL = null;
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            TrustedListFacade.newFacade().marshall(trustStatusListType, baos, false);
            modifiedUnsignedTL = new InMemoryDocument(baos.toByteArray());
        }
        modifiedUnsignedTL.save("target/unsigned_TL.xml");
        // end::demoSign[]

        assertTrue(new File("target/unsigned_TL.xml").delete());
    }

    @Test
    void editValidTrustedList() throws Exception {
        // tag::demoEdit[]
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.model.InMemoryDocument;
        // import eu.europa.esig.trustedlist.TrustedListFacade;
        // import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
        // import java.io.ByteArrayOutputStream;
        // import java.io.File;
        // import java.math.BigInteger;

        // Load original Trusted List
        final File file = new File("src/main/resources/trusted-list.xml");

        // Parse it to JAXB object
        final TrustStatusListType jaxbObject = TrustedListFacade.newFacade().unmarshall(file, false);
        assertNotNull(jaxbObject);

        // Modify JAXB Object where required
        jaxbObject.getSchemeInformation().setTSLSequenceNumber(new BigInteger("39"));

        // Store to file
        DSSDocument modifiedUnsignedTL;
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            TrustedListFacade.newFacade().marshall(jaxbObject, baos, false);
            modifiedUnsignedTL = new InMemoryDocument(baos.toByteArray());
        }
        modifiedUnsignedTL.save("target/unsigned_TL.xml");
        // end::demoEdit[]

        assertTrue(new File("target/unsigned_TL.xml").delete());
    }

}
