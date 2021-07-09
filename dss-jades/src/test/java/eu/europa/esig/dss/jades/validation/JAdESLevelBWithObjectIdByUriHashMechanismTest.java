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
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESLevelBWithObjectIdByUriHashMechanismTest extends AbstractJAdESTestValidation {

    private static final String DOC_NAME = "TEST-DOC.txt";

    private static final DSSDocument originalDocument = new InMemoryDocument("TL-039 Test Document".getBytes(), DOC_NAME);

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-flattened-BpB-detached-objectByURIHash.json");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(originalDocument);
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        boolean jwsSigningInputFound = false;
        boolean sigDEntryFound = false;
        for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
            if (DigestMatcherType.JWS_SIGNING_INPUT_DIGEST.equals(digestMatcher.getType())) {
                jwsSigningInputFound = true;
            } else if (DigestMatcherType.SIG_D_ENTRY.equals(digestMatcher.getType())) {
                assertNotNull(digestMatcher.getDigestMethod());
                assertNotNull(digestMatcher.getDigestValue());
                assertFalse(Arrays.equals(DSSUtils.digest(digestMatcher.getDigestMethod(), DSSUtils.toByteArray(originalDocument)),
                        digestMatcher.getDigestValue()));
                assertArrayEquals(DSSUtils.digest(digestMatcher.getDigestMethod(), DSSJsonUtils.toBase64Url(originalDocument).getBytes()), digestMatcher.getDigestValue());
                sigDEntryFound = true;
            }
        }
        assertTrue(jwsSigningInputFound);
        assertTrue(sigDEntryFound);
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
        assertEquals(1, signatureScopes.size());

        XmlSignatureScope signatureScope = signatureScopes.get(0);
        assertEquals(DOC_NAME, signatureScope.getName());
        assertNotNull(signatureScope.getDescription());
        assertEquals(SignatureScopeType.FULL, signatureScope.getScope());
        assertNotNull(signatureScope.getSignerData());
        XmlSignerData signerData = signatureScope.getSignerData();
        assertNotNull(signerData.getDigestAlgoAndValue());
        assertNotNull(signerData.getDigestAlgoAndValue().getDigestMethod());
        assertNotNull(signerData.getDigestAlgoAndValue().getDigestValue());

        assertArrayEquals(DSSUtils.digest(signerData.getDigestAlgoAndValue().getDigestMethod(),
                DSSUtils.toByteArray(originalDocument)), signerData.getDigestAlgoAndValue().getDigestValue());
    }

}
