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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESWithDoubleSigningTimeValidationTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cades-double-signing-time.p7m");
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean validSigFound = false;
        boolean invalidSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
            assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
            for (XmlDigestMatcher digestMatcher : digestMatchers) {
                if (!DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                    assertTrue(digestMatcher.isDataFound());
                    assertTrue(digestMatcher.isDataIntact());
                    assertFalse(digestMatcher.isDuplicated());
                }
            }

            if (signatureWrapper.isSignatureIntact()) {
                assertTrue(signatureWrapper.isSignatureValid());
                assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
                validSigFound = true;
            } else {
                assertFalse(signatureWrapper.isSignatureValid());
                assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
                invalidSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(invalidSigFound);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean validSigFound = false;
        boolean invalidSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.CAdES_BASELINE_B.equals(signatureWrapper.getSignatureFormat())) {
                validSigFound = true;
            } else if (SignatureLevel.CMS_NOT_ETSI.equals(signatureWrapper.getSignatureFormat())) {
                invalidSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(invalidSigFound);
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        boolean validSigFound = false;
        boolean invalidSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.getClaimedSigningTime() != null) {
                validSigFound = true;
            } else {
                // value is ignored
                invalidSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(invalidSigFound);
    }

}
