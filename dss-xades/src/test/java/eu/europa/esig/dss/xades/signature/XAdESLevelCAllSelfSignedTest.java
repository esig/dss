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

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.validationreport.jaxb.SACertIDListType;
import eu.europa.esig.validationreport.jaxb.SARevIDListType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.xades.definition.xades132.XAdES132Path;
import jakarta.xml.bind.JAXBElement;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelCAllSelfSignedTest extends XAdESLevelCTest {

    @Test
    @Override
    public void signAndVerify() {
        certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

        Exception exception = assertThrows(AlertException.class, () -> super.sign());
        assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
        assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

        certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new LogOnStatusAlert());

        super.signAndVerify();
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service = super.getService();
        service.setTspSource(getSelfSignedTsa());
        return service;
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        Document document = DomUtils.buildDOM(byteArray);
        NodeList signaturesList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(document);
        assertEquals(1, signaturesList.getLength());

        XAdES132Path paths = new XAdES132Path();

        Node signature = signaturesList.item(0);
        NodeList signingCertificateList = DomUtils.getNodeList(signature, paths.getSigningCertificateChildren());
        assertEquals(1, signingCertificateList.getLength());

        NodeList signingCertificateV2List = DomUtils.getNodeList(signature, paths.getSigningCertificateV2Children());
        assertEquals(0, signingCertificateV2List.getLength());

        NodeList completeCertificateRefsList = DomUtils.getNodeList(signature, paths.getCompleteCertificateRefsPath());
        assertEquals(1, completeCertificateRefsList.getLength());

        NodeList completeCertificateRefsV2List = DomUtils.getNodeList(signature, paths.getCompleteCertificateRefsV2Path());
        assertEquals(0, completeCertificateRefsV2List.getLength());

        NodeList completeRevocationRefsList = DomUtils.getNodeList(signature, paths.getCompleteRevocationRefsPath());
        assertEquals(0, completeRevocationRefsList.getLength());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        AdvancedSignature advancedSignature = signatures.get(0);

        Set<CertificateRef> certificateRefs = advancedSignature.getCertificateSource().getAllCertificateRefs();
        assertTrue(Utils.isCollectionNotEmpty(certificateRefs));
        for (CertificateRef certificateRef : certificateRefs) {
            assertNotNull(certificateRef.getCertDigest());
            assertNotNull(certificateRef.getCertificateIdentifier());
        }

        List<RevocationRef<OCSP>> ocspRefs = advancedSignature.getOCSPSource().getCompleteRevocationRefs();
        List<RevocationRef<CRL>> crlRefs = advancedSignature.getCRLSource().getCompleteRevocationRefs();

        assertTrue(Utils.isCollectionEmpty(ocspRefs) && Utils.isCollectionEmpty(crlRefs));
    }

    @Override
    protected void checkCertificates(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        List<RelatedCertificateWrapper> completeCertificatesRefs = foundCertificates.getRelatedCertificatesByRefOrigin(
                CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
        assertEquals(1, completeCertificatesRefs.size());

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
        assertEquals(0, foundRevocations.getOrphanRevocationRefs().size());
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
                assertEquals(1, certIdList.getAttributeObject().get(0).getVOReference().size());
                assertEquals(0, certIdList.getCertID().size());
                completeCertRefFound = true;
            }
            if ("CompleteRevocationRefs".equals(xmlElementName)) {
                SARevIDListType revIdList = (SARevIDListType) signatureAttributeObj.getValue();
                assertEquals(0, revIdList.getAttributeObject().size());
                assertEquals(0, revIdList.getCRLIDOrOCSPID().size());
                completeRevocRefFound = true;
            }
        }
        assertTrue(signCertRefFound);
        assertTrue(completeCertRefFound);
        assertFalse(completeRevocRefFound);
    }

    @Override
    protected String getSigningAlias() {
        return SELF_SIGNED_USER;
    }

}
