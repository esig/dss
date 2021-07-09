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

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESWithManifestDuplicatedReferenceTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss2329/xades-with-manifest-with-duplicated-reference.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(new FileDocument("src/test/resources/sample.png"),
                new FileDocument("src/test/resources/sample.txt"));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        int manifestCounter = 0;
        int manifestRefCounter = 0;
        int invalidRefCounter = 0;
        for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
            if (DigestMatcherType.MANIFEST.equals(digestMatcher.getType())) {
                assertFalse(digestMatcher.isDuplicated());
                assertTrue(digestMatcher.isDataIntact());
                assertEquals("r-manifest", digestMatcher.getName());
                ++manifestCounter;
            } else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                ++manifestRefCounter;
            }
            if (!digestMatcher.isDataFound()) {
                assertTrue(digestMatcher.isDuplicated());
                assertEquals("#o-id-1075588d58231c730f94fb897ed0d7a9-1", digestMatcher.getName());
                ++invalidRefCounter;
            } else {
                assertTrue(digestMatcher.isDataIntact());
            }
        }
        assertEquals(1, manifestCounter);
        assertEquals(3, manifestRefCounter);
        assertEquals(1, invalidRefCounter);
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isStructuralValidationValid());

        boolean duplicatedIdFound = false;
        for (String error : signature.getStructuralValidationMessages()) {
            if (error.contains("o-id-1075588d58231c730f94fb897ed0d7a9-1")) {
                duplicatedIdFound = true;
                break;
            }
        }
        assertTrue(duplicatedIdFound);
    }

}
