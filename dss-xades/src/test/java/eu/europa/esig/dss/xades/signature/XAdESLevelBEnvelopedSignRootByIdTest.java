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

import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

// See DSS-2919
class XAdESLevelBEnvelopedSignRootByIdTest extends AbstractXAdESTestSignature {

    private static final String ID_ELEMENT_TO_SIGN = "Element_0_ID";

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample-xml-stylesheet-with-id.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        DSSReference reference = new DSSReference();
        reference.setUri("#" + ID_ELEMENT_TO_SIGN);
        reference.setTransforms(Arrays.asList(
                new EnvelopedSignatureTransform(),
                new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE)));
        reference.setContents(documentToSign);
        signatureParameters.setReferences(Collections.singletonList(reference));

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected void checkDataObjectFormat(Document documentDOM) {
        super.checkDataObjectFormat(documentDOM);

        NodeList signatureNodeList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(documentDOM);
        assertEquals(1, signatureNodeList.getLength());

        Element signatureElement = (Element) signatureNodeList.item(0);
        NodeList dataObjectFormatList = DomUtils.getNodeList(signatureElement, new XAdES132Path().getDataObjectFormat());
        assertEquals(1, dataObjectFormatList.getLength());

        Element dataObjectFormat = (Element) dataObjectFormatList.item(0);
        String objectReference = dataObjectFormat.getAttribute(XAdES132Attribute.OBJECT_REFERENCE.getAttributeName());
        assertNotNull(objectReference);

        Element elementById = DomUtils.getElementById(signatureElement, DomUtils.getId(objectReference));
        assertNotNull(elementById);
        assertTrue(XMLDSigElement.REFERENCE.isSameTagName(elementById.getLocalName()));
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        Document originalDocument = DomUtils.buildDOM(documentToSign);
        Element elementById = DomUtils.getElementById(originalDocument, ID_ELEMENT_TO_SIGN);

        List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
        assertEquals(1, originalDocuments.size());
        Document signedElement = DomUtils.buildDOM(originalDocuments.get(0));

        assertArrayEquals(XMLCanonicalizer.createInstance(CanonicalizationMethod.EXCLUSIVE).canonicalize(elementById),
                XMLCanonicalizer.createInstance(CanonicalizationMethod.EXCLUSIVE).canonicalize(signedElement));
        assertFalse(Arrays.equals(XMLCanonicalizer.createInstance(CanonicalizationMethod.EXCLUSIVE).canonicalize(originalDocument),
                XMLCanonicalizer.createInstance(CanonicalizationMethod.EXCLUSIVE).canonicalize(signedElement)));
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