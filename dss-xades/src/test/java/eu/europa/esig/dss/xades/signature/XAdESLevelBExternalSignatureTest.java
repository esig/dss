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

import eu.europa.esig.dss.*;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.ExternalXAdESSignatureResult;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Date;

public class XAdESLevelBExternalSignatureTest extends AbstractPkiFactoryTestDocumentSignatureService<XAdESSignatureParameters> {
    private static final Logger LOG = LoggerFactory.getLogger(XAdESLevelBExternalSignatureTest.class);
    private DocumentSignatureService<XAdESSignatureParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @Before
    public void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setSignedPropertiesCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        signatureParameters.setSignedInfoCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        signatureParameters.setGenerateTBSWithoutCertificate(true);

        service = new XAdESService(getCompleteCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument toBeSigned = getDocumentToSign();
        XAdESSignatureParameters params = getSignatureParameters();
        DocumentSignatureService<XAdESSignatureParameters> service = getService();

        // Generate toBeSigned without signing certificate
        assert params.getSigningCertificate() == null;
        ToBeSigned dataToSign = service.getDataToSign(getDocumentToSign(), params);

        /**
         * Simulate an external process that (1) creates a XAdES-object which includes
         * signing certificate (2) updates SigningInfo structure in dataToSign and
         * (3) calculated signature value.
         */
        ExternalXAdESSignatureResult externalSignatureResult = simulateExternalSignature(dataToSign);

        /**
         * Construct new set of parameters including explicitly specified
         * signed data and AdES object created by external process.
         */
        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(externalSignatureResult.getSigningDate());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignedAdESObject(externalSignatureResult.getSignedAdESObject());
        signatureParameters.setSignedData(externalSignatureResult.getSignedData());

        // Sign document using signature value created by external process.
        return service.signDocument(toBeSigned, signatureParameters, externalSignatureResult.getSignatureValue());
    }

    private ExternalXAdESSignatureResult simulateExternalSignature(ToBeSigned toBeSigned){
        ExternalXAdESSignatureResult externalSignatureResult = new ExternalXAdESSignatureResult();

        // Get hold of signature certificate.
        X509Certificate signingCertificate = getSigningCert().getCertificate();
        externalSignatureResult.setSigningCertificate(signingCertificate);

        // Set signing date and calculate deterministic ID
        Date signingDate = new Date();
        externalSignatureResult.setSigningDate(signingDate);
        String deterministicId = DSSUtils.getDeterministicId(signingDate, getSigningCert().getDSSId());

        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            Document signedInfoDocument = documentBuilder.parse(new ByteArrayInputStream(toBeSigned.getBytes()));

            // Create XAdES object and include signing certificate
            Document signedPropertiesDocument = DSSXMLUtils.createXAdESObject(signingDate, signingCertificate, signatureParameters.getSignatureAlgorithm(), "r-id-1", MimeType.XML);
            XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();
            Element signedPropertiesElement = DomUtils.getElement(signedPropertiesDocument, xPathQueryHolder.XPATH_SIGNED_PROPERTIES);

            // Calculate new digest based on updated SignedProperties
            byte[] updatedDigest = DSSXMLUtils.calculateDigestValue(signedPropertiesElement, signatureParameters.getSignedPropertiesCanonicalizationMethod(),
                    signatureParameters.getDigestAlgorithm());

            // Locate and update digest and reference ID within signedInfo
            Element signedPropertiesReference = DSSXMLUtils.getSignedPropertiesReferenceElement(signedInfoDocument);
            DSSXMLUtils.updateReferenceURI(signedPropertiesReference, "#xades-" + deterministicId);
            DSSXMLUtils.updateReferenceDigestValue(signedPropertiesReference, updatedDigest);

            // Canonicalize and update toBeSigned
            toBeSigned.setBytes(DSSXMLUtils.canonicalizeSubtree(signatureParameters.getSignedInfoCanonicalizationMethod(), signedInfoDocument));
            externalSignatureResult.setSignedData(toBeSigned.getBytes());

            // Serialize XAdES object
            Element objectElement = DomUtils.getElement(signedPropertiesDocument, xPathQueryHolder.XPATH_OBJECT);
            externalSignatureResult.setSignedAdESObject(DSSXMLUtils.serializeNode(objectElement));

            // Calculate signature
            SignatureValue signatureValue = getToken().sign(toBeSigned, getSignatureParameters().getDigestAlgorithm(),
                    getSignatureParameters().getMaskGenerationFunction(), getPrivateKeyEntry());
            externalSignatureResult.setSignatureValue(signatureValue);
        } catch(Exception e){
            LOG.error("Error while simulating external XAdES signature", e);
        }

        return externalSignatureResult;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected MimeType getExpectedMime() {
        return MimeType.XML;
    }

    @Override
    protected boolean isBaselineT() {
        return false;
    }

    @Override
    protected boolean isBaselineLTA() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }
}
