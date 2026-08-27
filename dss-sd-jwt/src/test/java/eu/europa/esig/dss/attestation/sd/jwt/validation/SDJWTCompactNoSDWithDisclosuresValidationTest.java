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
package eu.europa.esig.dss.attestation.sd.jwt.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactNoSDWithDisclosuresValidationTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        String sdjwt = new String(DSSUtils.toByteArray(new FileDocument("src/test/resources/validation/sd-jwt-compact-no-sd.json")));
        sdjwt += "WyJaRUdzT2hyVFZIZXpIMEpSOXpyLTh3IiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyIzdFpCYVRVV09vcGdQZUNYM3J5YkZRIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~";
        return new InMemoryDocument(sdjwt.getBytes());
    }

    @Override
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        AttestationWrapper attestationWrapper = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        assertNotNull(attestationWrapper);

        List<XmlDigestMatcher> digestMatchers = attestationWrapper.getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertEquals(DigestMatcherType.SELECTIVE_DISCLOSURE, xmlDigestMatcher.getType());
            assertTrue(xmlDigestMatcher.isDataFound());
            assertFalse(xmlDigestMatcher.isDataIntact());
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            assertNotNull(xmlDigestMatcher.getDisclosableClaim().getName());
            assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
        }
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
    }

    @Override
    protected boolean orphanSelectiveDisclosuresPresent() {
        return true;
    }

}
