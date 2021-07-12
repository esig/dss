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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS2471Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/PAdES-LT.pdf"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        int tLevelSignatureCounter = 0;
        int ltLevelSignatureCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.PAdES_BASELINE_T.equals(signatureWrapper.getSignatureFormat())) {
                ++tLevelSignatureCounter;
            } else if (SignatureLevel.PAdES_BASELINE_LT.equals(signatureWrapper.getSignatureFormat())) {
                ++ltLevelSignatureCounter;
            }
        }
        assertEquals(1, tLevelSignatureCounter);
        assertEquals(2, ltLevelSignatureCounter);
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            List<RelatedCertificateWrapper> signingCertificates = timestampWrapper.foundCertificates()
                    .getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
            assertEquals(1, signingCertificates.size());
            assertEquals(2, signingCertificates.get(0).getReferences().size());
        }
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        Set<TimestampWrapper> allTimestamps = diagnosticData.getTimestampSet();
        for (TimestampWrapper timestampWrapper : allTimestamps) {
            assertNotNull(timestampWrapper.getProductionTime());
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());

            assertTrue(timestampWrapper.isSigningCertificateIdentified());
            assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
            assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
        }
    }

}
