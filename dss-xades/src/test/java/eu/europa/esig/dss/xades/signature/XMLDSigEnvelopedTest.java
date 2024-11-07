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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class XMLDSigEnvelopedTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        DSSReference reference = new DSSReference();
        reference.setId("r-id-1");
        reference.setUri("");

        reference.setTransforms(Arrays.asList(new EnvelopedSignatureTransform(), new CanonicalizationTransform(signatureParameters.getSignedInfoCanonicalizationMethod())));
        reference.setContents(documentToSign);
        signatureParameters.setReferences(Collections.singletonList(reference));

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        // get initial ToBeSigned
        ToBeSigned dataToSign = service.getDataToSign(getDocumentToSign(), getSignatureParameters());

        // Remove ds:Reference to SignedProperties
        Document signedInfoDom = DomUtils.buildDOM(dataToSign.getBytes());
        Element signedInfoElement = (Element) signedInfoDom.getFirstChild();
        NodeList childNodes = signedInfoElement.getChildNodes();
        Node referenceSignedProperties = childNodes.item(childNodes.getLength() - 1);
        signedInfoElement.removeChild(referenceSignedProperties);

        // Canonicalize the obtained ds:SignedInfo
        byte[] signedInfoBytes = XMLCanonicalizer.createInstance(signatureParameters.getSignedInfoCanonicalizationMethod()).canonicalize(signedInfoElement);

        SignatureValue signatureValue = getToken().sign(new ToBeSigned(signedInfoBytes), getSignatureParameters().getSignatureAlgorithm(), getPrivateKeyEntry());

        // remove cached values
        signatureParameters.reinit();

        // se reduced SignedInfo
        signatureParameters.setSignedData(signedInfoBytes);

        // sign document
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        // Remove ds:Object from ds:Signature
        Document signedDocumentDom = DomUtils.buildDOM(signedDocument);
        NodeList signaturesNodeList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(signedDocumentDom);
        Element signatureElement = (Element) signaturesNodeList.item(0);
        NodeList signatureChildNodes = signatureElement.getChildNodes();
        Node dsObject = signatureChildNodes.item(signatureChildNodes.getLength() - 1);
        signatureElement.removeChild(dsObject);

        // re-build the document with omitted ds:Object
        return new InMemoryDocument(DomUtils.serializeNode(signedDocumentDom), signedDocument.getName());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSigningCertificateIdentified());
        assertFalse(signature.isSigningCertificateReferencePresent());
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        assertNull(diagnosticData.getFirstSignatureDate());
    }

    @Override
    protected void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes) {
        assertNull(signatureAttributes);
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

}
