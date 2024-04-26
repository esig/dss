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

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.CommitmentQualifier;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.xades.DSSObject;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelBReSignOJManifestTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument signedOJ;
    private DSSDocument originalOJManifest;

    @BeforeEach
    public void init() throws Exception {
        signedOJ = new FileDocument("src/test/resources/validation/OJ_L_2016_294_FULL.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        DocumentValidator validator = new XMLDocumentValidator(signedOJ);
        AdvancedSignature signature = validator.getSignatures().iterator().next();
        List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signature);

        originalOJManifest = originalDocuments.get(0);

        DSSReference manifestReference = new DSSReference();
        manifestReference.setContents(originalOJManifest);
        manifestReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
        manifestReference.setType("http://www.w3.org/2000/09/xmldsig#Manifest");
        manifestReference.setId("r-manifest");
        manifestReference.setUri("#manifest");
        manifestReference.setTransforms(Collections.singletonList(new CanonicalizationTransform(CanonicalizationMethod.INCLUSIVE)));

        DSSObject manifestObject = new DSSObject();
        manifestObject.setContent(originalOJManifest);
        manifestObject.setMimeType("http://www.w3.org/2000/09/xmldsig#Manifest");
        manifestReference.setObject(manifestObject);

        DSSReference oldSignatureReference = new DSSReference();
        oldSignatureReference.setContents(signedOJ);
        oldSignatureReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
        oldSignatureReference.setType("http://www.w3.org/2000/09/xmldsig#Object");
        oldSignatureReference.setId("r-" + signatureParameters.getDeterministicId() + "-1");
        oldSignatureReference.setUri("#o-" +  signatureParameters.getDeterministicId() + "-1");
        oldSignatureReference.setTransforms(Collections.singletonList(new Base64Transform()));

        DSSObject oldSignatureReferenceObject = new DSSObject();
        oldSignatureReferenceObject.setId("o-" +  signatureParameters.getDeterministicId() + "-1");
        String base64EncodedSignedOJ = Utils.toBase64(DSSUtils.toByteArray(signedOJ));
        oldSignatureReferenceObject.setContent(new InMemoryDocument(base64EncodedSignedOJ.getBytes()));
        oldSignatureReference.setObject(oldSignatureReferenceObject);

        signatureParameters.setReferences(Arrays.asList(manifestReference, oldSignatureReference));

        Document commitmentTypeQualifierDocument = DomUtils.buildDOM();
        Element initialPublicationDateElement = commitmentTypeQualifierDocument.createElementNS(
                "http://some-server.eu/oj-initial-publication-date", "ext:InitialPublicationDate");
        initialPublicationDateElement.setTextContent(DSSUtils.formatDateToRFC(signature.getSigningTime()));
        commitmentTypeQualifierDocument.appendChild(initialPublicationDateElement);

        CommitmentQualifier commitmentQualifier = new CommitmentQualifier();
        commitmentQualifier.setContent(DomUtils.createDssDocumentFromDomDocument(commitmentTypeQualifierDocument, null));

        CommonCommitmentType commitmentType = new CommonCommitmentType();
        commitmentType.setUri("http://some-server.eu/oj-resigning");
        commitmentType.setCommitmentTypeQualifiers(commitmentQualifier);

        signatureParameters.bLevel().setCommitmentTypeIndications(Collections.singletonList(commitmentType));

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        String xmlContent = new String(byteArray);
        assertTrue(xmlContent.contains("<xades:CommitmentTypeIndication>"));
        assertTrue(xmlContent.contains("<xades:CommitmentTypeId>"));
        assertTrue(xmlContent.contains("<xades:Identifier>http://some-server.eu/oj-resigning</xades:Identifier>"));
        assertTrue(xmlContent.contains("<xades:AllSignedDataObjects/>"));
        assertTrue(xmlContent.contains("<xades:CommitmentTypeQualifiers>"));
        assertTrue(xmlContent.contains("<xades:CommitmentTypeQualifier>"));
        assertTrue(xmlContent.contains("<ext:InitialPublicationDate xmlns:ext=\"http://some-server.eu/oj-initial-publication-date\">2016-10-28T05:28:12Z</ext:InitialPublicationDate>"));

        assertTrue(xmlContent.contains("<ds:Object MimeType=\"http://www.w3.org/2000/09/xmldsig#Manifest\">"));
        assertTrue(xmlContent.contains("<ds:Manifest Id=\"manifest\">"));
        
        assertTrue(xmlContent.contains("<ds:Object Id=\"" + "o-" +  signatureParameters.getDeterministicId() + "-1" + "\">"));
        assertTrue(xmlContent.contains(Utils.toBase64(DSSUtils.toByteArray(signedOJ))));

        Document document = DomUtils.buildDOM(byteArray);
        Element oldSignatureDocumentElement = DomUtils.getElementById(document.getDocumentElement(),
                "o-" + signatureParameters.getDeterministicId() + "-1");
        assertNotNull(oldSignatureDocumentElement);

        DSSDocument oldSignatureDocument = new InMemoryDocument(Utils.fromBase64(oldSignatureDocumentElement.getTextContent()));
        DocumentValidator documentValidator = new XMLDocumentValidator(oldSignatureDocument);
        assertEquals(1, documentValidator.getSignatures().size());
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
        return originalOJManifest;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
