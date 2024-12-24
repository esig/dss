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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.CommonObjectIdentifier;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.dataobject.DSSDataObjectFormat;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import org.apache.xml.security.signature.Reference;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XAdESLevelBEnvelopingCustomDataObjectFormatTest extends AbstractXAdESTestSignature {

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
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        List<DSSTransform> transforms = new ArrayList<>();
        Base64Transform dssTransform = new Base64Transform();
        transforms.add(dssTransform);

        DSSReference ref1 = new DSSReference();
        ref1.setContents(documentToSign);
        ref1.setId("r-" + documentToSign.getName());
        ref1.setTransforms(transforms);
        ref1.setType(Reference.OBJECT_URI);
        ref1.setUri('#' + documentToSign.getName());
        ref1.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);

        signatureParameters.setReferences(Collections.singletonList(ref1));

        signatureParameters.setDataObjectFormatList(Collections.singletonList(new DSSDataObjectFormat()));

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        Exception exception = assertThrows(IllegalArgumentException.class, super::sign);
        assertEquals("At least one of the Description, ObjectIdentifier or MimeType " +
                "shall be defined for a DataObjectFormat object!", exception.getMessage());

        DSSDataObjectFormat dof1 = new DSSDataObjectFormat();

        dof1.setMimeType(MimeTypeEnum.XML.getMimeTypeString());
        dof1.setEncoding("http://www.w3.org/2000/09/xmldsig#base64");
        dof1.setDescription("This is a sample XML signed document");

        CommonObjectIdentifier objectIdentifier = new CommonObjectIdentifier();
        objectIdentifier.setUri(documentToSign.getName());
        objectIdentifier.setDocumentationReferences("http://nowina.lu/docs/sample.xml");
        dof1.setObjectIdentifier(objectIdentifier);

        signatureParameters.setDataObjectFormatList(Collections.singletonList(dof1));

        exception = assertThrows(IllegalArgumentException.class, super::sign);
        assertEquals("ObjectReference attribute of DataObjectFormat shall be present!", exception.getMessage());

        dof1.setObjectReference("r-" + documentToSign.getName());

        exception = assertThrows(IllegalArgumentException.class, super::sign);
        assertEquals("ObjectReference attribute of DataObjectFormat shall define a reference to an element " +
                "within signature (i.e. shall begin with '#')!", exception.getMessage());

        dof1.setObjectReference("#r-" + documentToSign.getName());

        return super.sign();
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