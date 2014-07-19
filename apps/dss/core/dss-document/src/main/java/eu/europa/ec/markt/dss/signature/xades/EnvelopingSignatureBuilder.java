/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.xades;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DSSSignatureUtils;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;

/**
 * This class handles the specifics of the enveloping XML signature
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
class EnvelopingSignatureBuilder extends SignatureBuilder {

    /**
     * The default constructor for EnvelopingSignatureBuilder. The enveloped signature uses by default the inclusive
     * method of canonicalization.
     *
     * @param params  The set of parameters relating to the structure and process of the creation or extension of the
     *                electronic signature.
     * @param origDoc The original document to sign.
     */
    public EnvelopingSignatureBuilder(SignatureParameters params, DSSDocument origDoc) {

        super(params, origDoc);
        signedInfoCanonicalizationMethod = CanonicalizationMethod.INCLUSIVE;
        reference2CanonicalizationMethod = CanonicalizationMethod.INCLUSIVE;
    }

    /**
     * This method creates the first reference (this is a reference to the file to sign) witch is specific for each form
     * of signature. Here, the value of the URI is an unique identifier to the base64 encoded data (file). The data are
     * included in the signature XML.
     *
     * @throws DSSException
     */
    @Override
    protected void incorporateReference1() throws DSSException {

        //<ds:Reference Id="signed-data-ref" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#signed-data-idfc5ff27ee49763d9ba88ba5bbc49f732">
        final Element referenceDom = DSSXMLUtils.addElement(documentDom, signedInfoDom, XMLSignature.XMLNS, "ds:Reference");
        referenceDom.setAttribute("Id", "signed-data-ref");
        referenceDom.setAttribute("Type", "http://www.w3.org/2000/09/xmldsig#Object");
        referenceDom.setAttribute("URI", "#signed-data-" + deterministicId);

        final Element transformsDom = DSSXMLUtils.addElement(documentDom, referenceDom, XMLSignature.XMLNS, "ds:Transforms");

        final Element transform1Dom = DSSXMLUtils.addElement(documentDom, transformsDom, XMLSignature.XMLNS, "ds:Transform");
        transform1Dom.setAttribute("Algorithm", CanonicalizationMethod.BASE64);

        // <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
        incorporateDigestMethod(referenceDom, digestAlgorithm);

	    final InMemoryDocument inMemoryDocument = new InMemoryDocument(originalDocument.getBytes());
	    incorporateDigestValue(referenceDom, digestAlgorithm, inMemoryDocument);
    }

    /**
     * Adds signature value to the signature and returns XML signature (InMemoryDocument)
     *
     * @param signatureValue
     * @return
     * @throws DSSException
     */
    @Override
    public DSSDocument signDocument(final byte[] signatureValue) throws DSSException {

        if (!built) {

            build();
        }

        final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
        final byte[] signatureValueBytes = DSSSignatureUtils.convertToXmlDSig(encryptionAlgorithm, signatureValue);
        final String signatureValueBase64Encoded = DSSUtils.base64Encode(signatureValueBytes);
        final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
        signatureValueDom.appendChild(signatureValueNode);

        // <ds:Object>
        final String base64EncodedOriginalDocument = DSSUtils.base64Encode(originalDocument);
        final Element objectDom = DSSXMLUtils.addTextElement(documentDom, signatureDom, XMLSignature.XMLNS, "ds:Object", base64EncodedOriginalDocument);
        objectDom.setAttribute("Id", "signed-data-" + deterministicId);

        byte[] documentBytes = DSSXMLUtils.transformDomToByteArray(documentDom);
        final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
        return inMemoryDocument;
    }

    /**
     * This method returns data format reference specific for enveloped signature.
     */
    @Override
    protected String getDataObjectFormatObjectReference() {

        return "#signed-data-ref";
    }

    /**
     * This method returns data format mime type specific for enveloped signature.
     */
    @Override
    protected String getDataObjectFormatMimeType() {

        return "text/plain";
    }
}