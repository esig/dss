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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESDetachedByUriByHashWithURLEncodedParsTest extends AbstractJAdESTestValidation {

    private static final String DOC_ONE_NAME = "https://signature-plugtests.etsi.org/pub/JAdES/ObjectIdByURIHash-1.html";
    private static final String DOC_TWO_NAME = "https://signature-plugtests.etsi.org/pub/JAdES/ObjectIdByURIHash-2.html";

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-detached-by-uri-hash-encoded-pars.json");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        DSSDocument documentOne = new FileDocument("src/test/resources/ObjectIdByURIHash-1.html");
        documentOne.setName(DOC_ONE_NAME);
        DSSDocument documentTwo = new FileDocument("src/test/resources/ObjectIdByURIHash-2.html");
        documentTwo.setName(DOC_TWO_NAME);
        return Arrays.asList(documentOne, documentTwo);
    }

    @Override
    protected void checkDigestMatchers(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        boolean docOneFound = false;
        boolean docTwoFound = false;
        for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
            if (DigestMatcherType.SIG_D_ENTRY == digestMatcher.getType()) {
                if (DOC_ONE_NAME.equals(digestMatcher.getDocumentName())) {
                    assertNotNull(digestMatcher.getUri());
                    assertNotEquals(digestMatcher.getDocumentName(), digestMatcher.getUri());
                    docOneFound = true;
                } else if (DOC_TWO_NAME.equals(digestMatcher.getDocumentName())) {
                    assertNotNull(digestMatcher.getUri());
                    assertNotEquals(digestMatcher.getDocumentName(), digestMatcher.getUri());
                    docTwoFound = true;
                }
            }
            assertTrue(digestMatcher.isDataFound());
            assertTrue(digestMatcher.isDataIntact());
        }
        assertTrue(docOneFound);
        assertTrue(docTwoFound);
    }

}
