/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.validation.dss1334;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1334WrongNameTest extends AbstractXAdESTestValidation {

    private static final DSSDocument ORIGINAL_FILE = new FileDocument("src/test/resources/validation/dss1334/simple-test.xml");

    @BeforeEach
    public void init() {
        ORIGINAL_FILE.setName("wrong-name.xml");
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss1334/simple-test-signed-xades-baseline-b.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(ORIGINAL_FILE);
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
        assertEquals(2, Utils.collectionSize(digestMatchers));

        boolean signedDocumentFound = false;
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            if (DigestMatcherType.REFERENCE == digestMatcher.getType()) {
                assertEquals("r-id-1", digestMatcher.getId());
                assertEquals("simple-test.xml", digestMatcher.getUri());
                assertEquals(ORIGINAL_FILE.getName(), digestMatcher.getDocumentName());
                assertNotEquals(digestMatcher.getUri(), digestMatcher.getDocumentName());

                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());

                assertEquals(DigestAlgorithm.SHA1, digestMatcher.getDigestMethod());
                assertArrayEquals(ORIGINAL_FILE.getDigestValue(DigestAlgorithm.SHA1), digestMatcher.getDigestValue());

                signedDocumentFound = true;

            } else {
                assertEquals(DigestMatcherType.SIGNED_PROPERTIES, digestMatcher.getType());
            }
        }
        assertTrue(signedDocumentFound);
    }

}
