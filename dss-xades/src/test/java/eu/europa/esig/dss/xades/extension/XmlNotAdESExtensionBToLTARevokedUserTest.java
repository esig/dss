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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.xmldsig.definition.XMLDSigElement;
import eu.europa.esig.xmldsig.definition.XMLDSigNamespace;
import eu.europa.esig.xmldsig.definition.XMLDSigPath;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XmlNotAdESExtensionBToLTARevokedUserTest extends AbstractXAdESTestExtension {

    private XAdESService extensionService;

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_B;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setGenerateTBSWithoutCertificate(true);
        return signatureParameters;
    }

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        DSSDocument signedDocument = super.getSignedDocument(doc);
        Document docDom = DomUtils.buildDOM(signedDocument);
        NodeList signatures = DomUtils.getNodeList(docDom, XMLDSigPath.ALL_SIGNATURES_PATH);
        assertEquals(1, signatures.getLength());
        Node signatureElement = signatures.item(0);
        Node signatureValueNode = DomUtils.getElement(signatureElement, XMLDSigPath.SIGNATURE_VALUE_PATH);
        final Element keyInfoDom = DomUtils.createElementNS(docDom, XMLDSigNamespace.NS, XMLDSigElement.KEY_INFO);
        signatureValueNode.getParentNode().insertBefore(keyInfoDom, signatureValueNode.getNextSibling());
        for (CertificateToken token : getCertificateChain()) {
            // <ds:X509Data>
            final Element x509DataDom = DomUtils.createElementNS(docDom, XMLDSigNamespace.NS, XMLDSigElement.X509_DATA);
            keyInfoDom.appendChild(x509DataDom);
            DomUtils.addTextElement(docDom, x509DataDom, XMLDSigNamespace.NS, XMLDSigElement.X509_SUBJECT_NAME, token.getSubject().getRFC2253());
            DomUtils.addTextElement(docDom, x509DataDom, XMLDSigNamespace.NS, XMLDSigElement.X509_CERTIFICATE, Utils.toBase64(token.getEncoded()));
        }
        return DomUtils.createDssDocumentFromDomDocument(docDom, signedDocument.getName());
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LTA;
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        assertFalse(signatureWrapper.isSigningCertificateIdentified());
        assertFalse(signatureWrapper.isSigningCertificateReferencePresent());
        assertFalse(signatureWrapper.isSigningCertificateReferenceUnique());

        CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
        assertNull(signingCertificateReference);

        CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
        assertNotNull(signingCertificate);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected XAdESService getSignatureServiceToExtend() {
        return extensionService;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setAlertOnRevokedCertificate(new ExceptionOnStatusAlert());
        extensionService = new XAdESService(certificateVerifier);
        extensionService.setTspSource(getUsedTSPSourceAtExtensionTime());

        Exception exception = assertThrows(AlertException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));

        certificateVerifier.setAlertOnRevokedCertificate(new LogOnStatusAlert());
        return super.extendSignature(signedDocument);
    }

    @Override
    protected void checkOriginalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getFirstSignatureFormat());

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<TimestampWrapper> timestampList = signature.getTimestampList();
        assertEquals(0, timestampList.size());
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getFirstSignatureFormat());

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<TimestampWrapper> timestampList = signature.getTimestampList();
        assertEquals(2, timestampList.size());
        assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestampList.get(0).getType());
        assertEquals(TimestampType.ARCHIVE_TIMESTAMP, timestampList.get(1).getType());
    }

    @Override
    protected String getSigningAlias() {
        return REVOKED_USER;
    }

}