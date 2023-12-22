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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.validationreport.jaxb.SACertIDListType;
import eu.europa.esig.validationreport.jaxb.SARevIDListType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;

import jakarta.xml.bind.JAXBElement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelCSelfSignedUserTest extends XAdESLevelCTest {

    @Override
    protected String getSigningAlias() {
        return SELF_SIGNED_USER;
    }

    @Override
    protected void checkCertificates(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        List<RelatedCertificateWrapper> completeCertificatesRefs = foundCertificates.getRelatedCertificatesByRefOrigin(
                CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
        assertEquals(2, completeCertificatesRefs.size());

        for (RelatedCertificateWrapper certificateWrapper : completeCertificatesRefs) {
            for (CertificateRefWrapper certificateRefWrapper : certificateWrapper.getReferences()) {
                assertEquals(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS, certificateRefWrapper.getOrigin());
                assertNotEquals(CertificateRefOrigin.SIGNING_CERTIFICATE, certificateRefWrapper.getOrigin());
                assertEquals(signatureParameters.getTokenReferencesDigestAlgorithm(),
                        certificateRefWrapper.getDigestAlgoAndValue().getDigestMethod());
            }
        }

        List<RelatedCertificateWrapper> signingCertificatesRefs = foundCertificates.getRelatedCertificatesByRefOrigin(
                CertificateRefOrigin.SIGNING_CERTIFICATE);
        assertEquals(1, signingCertificatesRefs.size());

        for (RelatedCertificateWrapper certificateWrapper : signingCertificatesRefs) {
            for (CertificateRefWrapper certificateRefWrapper : certificateWrapper.getReferences()) {
                assertNotEquals(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS, certificateRefWrapper.getOrigin());
                assertEquals(CertificateRefOrigin.SIGNING_CERTIFICATE, certificateRefWrapper.getOrigin());
                assertEquals(signatureParameters.getSigningCertificateDigestMethod(),
                        certificateRefWrapper.getDigestAlgoAndValue().getDigestMethod());
            }
        }
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundRevocationsProxy foundRevocations = signature.foundRevocations();

        assertEquals(0, foundRevocations.getRelatedRevocationRefs().size());
        assertEquals(1, foundRevocations.getOrphanRevocationRefs().size());
        for (RevocationRefWrapper revocationRefWrapper: foundRevocations.getOrphanRevocationRefs()) {
            assertEquals(RevocationRefOrigin.COMPLETE_REVOCATION_REFS, revocationRefWrapper.getOrigins().get(0));
            assertEquals(signatureParameters.getTokenReferencesDigestAlgorithm(),
                    revocationRefWrapper.getDigestAlgoAndValue().getDigestMethod());
        }
    }

    @Override
    protected void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes) {
        boolean signCertRefFound = false;
        boolean completeCertRefFound = false;
        boolean completeRevocRefFound = false;

        List<JAXBElement<?>> signatureAttributeObjects = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
        for (JAXBElement<?> signatureAttributeObj : signatureAttributeObjects) {
            String xmlElementName = signatureAttributeObj.getName().getLocalPart();
            if ("SigningCertificate".equals(xmlElementName)) {
                SACertIDListType certIdList = (SACertIDListType) signatureAttributeObj.getValue();
                assertTrue(certIdList.isSigned());
                assertEquals(1, certIdList.getAttributeObject().size());
                assertEquals(1, certIdList.getAttributeObject().get(0).getVOReference().size());
                assertEquals(0, certIdList.getCertID().size());
                signCertRefFound = true;
            }
            if ("CompleteCertificateRefs".equals(xmlElementName)) {
                SACertIDListType certIdList = (SACertIDListType) signatureAttributeObj.getValue();
                assertEquals(1, certIdList.getAttributeObject().size());
                assertEquals(2, certIdList.getAttributeObject().get(0).getVOReference().size());
                assertEquals(0, certIdList.getCertID().size());
                completeCertRefFound = true;
            }
            if ("CompleteRevocationRefs".equals(xmlElementName)) {
                SARevIDListType revIdList = (SARevIDListType) signatureAttributeObj.getValue();
                assertEquals(0, revIdList.getAttributeObject().size());
                assertEquals(1, revIdList.getCRLIDOrOCSPID().size());
                completeRevocRefFound = true;
            }
        }
        assertTrue(signCertRefFound);
        assertTrue(completeCertRefFound);
        assertTrue(completeRevocRefFound);

    }

}
