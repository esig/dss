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
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.apache.xml.security.c14n.Canonicalizer;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.MessageDigest;
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
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
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
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setSigningCertificate(getSigningCert());
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
            Document signedPropertiesDocument = documentBuilder.newDocument();
            Element objectElement = signedPropertiesDocument.createElementNS(XMLSignature.XMLNS, XAdESBuilder.DS_OBJECT);
            signedPropertiesDocument.appendChild(objectElement);

            Element qualifyingProperties = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_QUALIFYING_PROPERTIES);
            qualifyingProperties.setAttribute(XAdESBuilder.TARGET, "#" + deterministicId);
            objectElement.appendChild(qualifyingProperties);

            Element signedPropertiesElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_SIGNED_PROPERTIES);
            signedPropertiesElement.setAttribute(XAdESBuilder.ID, "xades-" + deterministicId);
            qualifyingProperties.appendChild(signedPropertiesElement);

            Element signedSignaturePropertiesElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_SIGNED_SIGNATURE_PROPERTIES);
            signedPropertiesElement.appendChild(signedSignaturePropertiesElement);
            Element signingTimeElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_SIGNING_TIME);
            final XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(signingDate);
            final String xmlSigningTime = xmlGregorianCalendar.toXMLFormat();
            signingTimeElement.appendChild(signedPropertiesDocument.createTextNode(xmlSigningTime));
            signedSignaturePropertiesElement.appendChild(signingTimeElement);

            Element signingCertificateV2Element = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, "xades:SigningCertificateV2");
            Element certElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_CERT);
            Element certDigestElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_CERT_DIGEST);
            Element digestMethodElement = signedPropertiesDocument.createElementNS(XMLSignature.XMLNS, XAdESBuilder.DS_DIGEST_METHOD);
            digestMethodElement.setAttribute(XAdESBuilder.ALGORITHM, signatureParameters.getSignatureAlgorithm().getXMLId());
            certDigestElement.appendChild(digestMethodElement);
            Element digestValueElement = signedPropertiesDocument.createElementNS(XMLSignature.XMLNS, XAdESBuilder.DS_DIGEST_VALUE);
            byte[] certDigestValue = MessageDigest.getInstance(signatureParameters.getDigestAlgorithm().getJavaName()).digest(signingCertificate.getEncoded());
            digestValueElement.appendChild(signedPropertiesDocument.createTextNode(new String(Base64.encode(certDigestValue))));
            certDigestElement.appendChild(digestValueElement);
            certElement.appendChild(certDigestElement);
            Element issuerSerialV2Element = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_ISSUER_SERIAL_V2);
            X500Name issuerX500Name = new X509CertificateHolder(signingCertificate.getEncoded()).getIssuer();
            GeneralName generalName = new GeneralName(issuerX500Name);
            GeneralNames generalNames = new GeneralNames(generalName);
            BigInteger serialNumber = signingCertificate.getSerialNumber();
            IssuerSerial issuerSerial = new IssuerSerial(generalNames, new ASN1Integer(serialNumber));
            issuerSerialV2Element.appendChild(signedPropertiesDocument.createTextNode(new String(Base64.encode(issuerSerial.toASN1Primitive().getEncoded(ASN1Encoding.DER)))));
            certElement.appendChild(issuerSerialV2Element);
            signingCertificateV2Element.appendChild(certElement);
            signedSignaturePropertiesElement.appendChild(signingCertificateV2Element);

            Element signedDataObjectProperties = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_SIGNED_DATA_OBJECT_PROPERTIES);
            Element dataObjectFormatElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_DATA_OBJECT_FORMAT);
            dataObjectFormatElement.setAttribute("Reference", "#r-id-1");
            Element mimeTypeElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_MIME_TYPE);
            mimeTypeElement.appendChild(signedPropertiesDocument.createTextNode(MimeType.XML.getMimeTypeString()));
            dataObjectFormatElement.appendChild(mimeTypeElement);
            signedDataObjectProperties.appendChild(dataObjectFormatElement);
            signedPropertiesElement.appendChild(signedDataObjectProperties);

            // Calculate new digest based on updated SignedProperties
            Canonicalizer c14n = Canonicalizer.getInstance(signatureParameters.getSignedPropertiesCanonicalizationMethod());
            byte[] canonicalized = c14n.canonicalizeSubtree(signedPropertiesElement);
            MessageDigest messageDigest = MessageDigest.getInstance(signatureParameters.getDigestAlgorithm().getJavaName());
            byte[] updatedDigest = messageDigest.digest(canonicalized);

            // Locate and update digest and reference ID within signedInfo
            NodeList references = signedInfoDocument.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
            for (int i = 0; i < references.getLength(); i++) {
                Element reference = ((Element) references.item(i));
                String type = reference.getAttribute(XAdESBuilder.TYPE);
                if (type != null && type.equalsIgnoreCase("http://uri.etsi.org/01903#SignedProperties")) {
                    reference.setAttribute(XAdESBuilder.URI, "#xades-" + deterministicId);
                    Element element = (Element)reference.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestValue").item(0);
                    element.getFirstChild().setNodeValue(new String(Base64.encode(updatedDigest), "UTF-8"));
                }
            }

            // Canonicalize and update toBeSigned
            c14n = Canonicalizer.getInstance(signatureParameters.getSignedInfoCanonicalizationMethod());
            toBeSigned.setBytes(c14n.canonicalizeSubtree(signedInfoDocument));
            externalSignatureResult.setSignedData(toBeSigned.getBytes());

            // Transform XAdES object
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            DOMSource source = new DOMSource(objectElement);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            StreamResult streamResult = new StreamResult(baos);
            transformer.transform(source, streamResult);
            externalSignatureResult.setSignedAdESObject(baos.toByteArray());

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
