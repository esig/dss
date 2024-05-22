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
package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.validation.UserFriendlyIdentifierProvider;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ASiCECAdESLevelLTAWithUserFriendlyIdentifiersTest extends ASiCECAdESLevelLTATest {

    @Override
    protected TokenIdentifierProvider getTokenIdentifierProvider() {
        return new UserFriendlyIdentifierProvider();
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);

        assertEquals(1, advancedSignatures.size());
        AdvancedSignature advancedSignature = advancedSignatures.get(0);
        SignatureWrapper signature = diagnosticData.getSignatureById(advancedSignature.getId());
        assertNull(signature);

        signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);
        assertTrue(signature.getId().contains("SIGNATURE"));
        assertTrue(signature.getId().contains(signature.getSigningCertificate().getCommonName()));
        assertTrue(signature.getId().contains(
                DSSUtils.formatDateWithCustomFormat(signature.getClaimedSigningTime(), "yyyyMMdd-HHmm")));

        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getUsedCertificates()));
        for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
            assertTrue(certificateWrapper.getId().contains("CERTIFICATE"));
            assertTrue(certificateWrapper.getId().contains(certificateWrapper.getCommonName()));
            assertTrue(certificateWrapper.getId().contains(
                    DSSUtils.formatDateWithCustomFormat(certificateWrapper.getNotBefore(), "yyyyMMdd-HHmm")));
        }

        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getAllRevocationData()));
        for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
            if (RevocationType.CRL.equals(revocationWrapper.getRevocationType())) {
                assertTrue(revocationWrapper.getId().contains("CRL"));
            } else if (RevocationType.OCSP.equals(revocationWrapper.getRevocationType())) {
                assertTrue(revocationWrapper.getId().contains("OCSP"));
            } else {
                fail("Unsupported Revocation type found : " + revocationWrapper.getRevocationType());
            }
            assertTrue(revocationWrapper.getId().contains(revocationWrapper.getSigningCertificate().getCommonName()));
            assertTrue(revocationWrapper.getId().contains(
                    DSSUtils.formatDateWithCustomFormat(revocationWrapper.getProductionDate(), "yyyyMMdd-HHmm")));
        }

        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getTimestampList()));
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            assertTrue(timestampWrapper.getId().contains("TIMESTAMP"));
            assertTrue(timestampWrapper.getId().contains(timestampWrapper.getSigningCertificate().getCommonName()));
            assertTrue(timestampWrapper.getId().contains(
                    DSSUtils.formatDateWithCustomFormat(timestampWrapper.getProductionTime(), "yyyyMMdd-HHmm")));
        }

        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getOriginalSignerDocuments()));
        for (SignerDataWrapper signerDataWrapper: diagnosticData.getOriginalSignerDocuments()) {
            assertTrue(signerDataWrapper.getId().contains("DOCUMENT"));
            assertTrue(signerDataWrapper.getId().contains(
                    DSSUtils.replaceAllNonAlphanumericCharacters(signerDataWrapper.getReferencedName(), "-")));
        }
    }

}
