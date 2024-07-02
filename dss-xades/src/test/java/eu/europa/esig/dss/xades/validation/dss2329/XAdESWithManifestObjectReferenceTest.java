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
package eu.europa.esig.dss.xades.validation.dss2329;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESWithManifestObjectReferenceTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss2329/xades-with-manifest-with-object-reference.xml");
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        int manifestCounter = 0;
        int manifestRefCounter = 0;
        for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
            assertTrue(digestMatcher.isDataFound());
            assertTrue(digestMatcher.isDataIntact());
            if (DigestMatcherType.MANIFEST.equals(digestMatcher.getType())) {
                assertEquals("r-manifest", digestMatcher.getId());
                assertEquals("#manifest", digestMatcher.getUri());
                ++manifestCounter;
            } else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                assertNull(digestMatcher.getId());
                assertEquals("#o-id-1075588d58231c730f94fb897ed0d7a9-1", digestMatcher.getUri());
                ++manifestRefCounter;
            }
        }
        assertEquals(1, manifestCounter);
        assertEquals(1, manifestRefCounter);
    }

}
