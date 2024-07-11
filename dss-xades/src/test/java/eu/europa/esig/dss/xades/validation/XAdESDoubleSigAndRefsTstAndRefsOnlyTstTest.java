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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESDoubleSigAndRefsTstAndRefsOnlyTstTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument(new File("src/test/resources/validation/xades-level-x-double-sigAndRefsTst-refsOnlyTst.xml"));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(5, timestampList.size());

        int sigTstCounter = 0;
        int sigAndRefsTstCounter = 0;
        int refsOnlyTstCounter = 0;

        int previousRefsOnlyTstRefsAmount = 0;

        for (TimestampWrapper timestampWrapper : timestampList) {
            int timestampedSignaturesAmount = timestampWrapper.getTimestampedSignatures().size();
            int timestampedCertificatesAmount = timestampWrapper.getTimestampedCertificates().size() +
                    timestampWrapper.getTimestampedOrphanCertificates().size();
            int timestampedRevocationsAmount = timestampWrapper.getTimestampedRevocations().size() +
                    timestampWrapper.getTimestampedOrphanRevocations().size();
            int timestampedTimestampsAmount = timestampWrapper.getTimestampedTimestamps().size();

            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertEquals(1, timestampedSignaturesAmount);
                assertTrue(timestampedCertificatesAmount > 0);
                assertFalse(timestampedRevocationsAmount > 0);
                assertFalse(timestampedTimestampsAmount > 0);
                ++sigTstCounter;

            } else if (TimestampType.VALIDATION_DATA_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertEquals(1, timestampedSignaturesAmount);
                assertTrue(timestampedCertificatesAmount > 0);
                assertTrue(timestampedRevocationsAmount > 0);
                assertEquals(1, timestampedTimestampsAmount);
                ++sigAndRefsTstCounter;

            } else if (TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertEquals(0, timestampedSignaturesAmount);
                assertTrue(timestampedCertificatesAmount > 0);
                assertTrue(timestampedRevocationsAmount > 0);
                assertEquals(0, timestampedTimestampsAmount);
                assertTrue(timestampedCertificatesAmount > previousRefsOnlyTstRefsAmount);
                previousRefsOnlyTstRefsAmount = timestampedCertificatesAmount;
                ++refsOnlyTstCounter;
            }

        }
        assertEquals(1, sigTstCounter);
        assertEquals(2, sigAndRefsTstCounter);
        assertEquals(2, refsOnlyTstCounter);
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        assertEquals(3, foundCertificates.getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size() +
                foundCertificates.getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());

        FoundRevocationsProxy foundRevocations = signature.foundRevocations();
        assertEquals(2, foundRevocations.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size() +
                foundRevocations.getOrphanRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
        assertEquals(1, foundRevocations.getRelatedRevocationsByType(RevocationType.CRL).size() +
                foundRevocations.getOrphanRevocationsByType(RevocationType.CRL).size());
        assertEquals(1, foundRevocations.getRelatedRevocationsByType(RevocationType.OCSP).size() +
                foundRevocations.getOrphanRevocationsByType(RevocationType.OCSP).size());
    }

}
