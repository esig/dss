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

import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;

/**
 * This class handles the specifics of the enveloping XML signature
 *
 */
class EnvelopingSignatureBuilder extends XAdESSignatureBuilder {

	/**
	 * The default constructor for EnvelopingSignatureBuilder. The enveloped signature uses by default the inclusive
	 * method of canonicalization.
	 * 
	 * @param params
	 *            The set of parameters relating to the structure and process of the creation or extension of the
	 *            electronic signature.
	 * @param origDoc
	 *            The original document to sign.
	 * @param certificateVerifier
	 */
	public EnvelopingSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument origDoc, final CertificateVerifier certificateVerifier) {
		super(params, origDoc, certificateVerifier);
		setCanonicalizationMethods(params, CanonicalizationMethod.INCLUSIVE);
	}

	@Override
	protected DSSReference createReference(DSSDocument document, int referenceIndex) {
		// <ds:Reference Id="signed-data-ref" Type="http://www.w3.org/2000/09/xmldsig#Object"
		// URI="#signed-data-idfc5ff27ee49763d9ba88ba5bbc49f732">
		final String suffix = deterministicId + "-" + referenceIndex;
		final DSSReference reference = new DSSReference();
		reference.setId(REFERENCE_ID_SUFFIX + suffix);
		reference.setContents(document);
		DigestAlgorithm digestAlgorithm = getReferenceDigestAlgorithmOrDefault(params);
		reference.setDigestMethodAlgorithm(digestAlgorithm);

		if (params.isManifestSignature()) {
			reference.setType(XMLDSigPaths.MANIFEST_TYPE);
			Document manifestDoc = DomUtils.buildDOM(document);
			Element manifestElement = manifestDoc.getDocumentElement();
			reference.setUri("#" + manifestElement.getAttribute(XMLDSigAttribute.ID.getAttributeName()));
			DSSTransform xmlTransform = new CanonicalizationTransform(getXmldsigNamespace(), Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
			reference.setTransforms(Arrays.asList(xmlTransform));
		} else if (params.isEmbedXML()) {
			reference.setType(XMLDSigPaths.OBJECT_TYPE);
			reference.setUri("#" + OBJECT_ID_SUFFIX + suffix);

			DSSTransform xmlTransform = new CanonicalizationTransform(getXmldsigNamespace(), Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
			reference.setTransforms(Arrays.asList(xmlTransform));
		} else {
			reference.setType(XMLDSigPaths.OBJECT_TYPE);
			reference.setUri("#" + OBJECT_ID_SUFFIX + suffix);

			DSSTransform base64Transform = new Base64Transform(getXmldsigNamespace());
			reference.setTransforms(Arrays.asList(base64Transform));
		}
		return reference;
	}

	@Override
	protected DSSDocument transformReference(final DSSReference reference) {
		return reference.getContents();
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
		final String signatureValueBase64Encoded = Utils.toBase64(signatureValueBytes);
		final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
		signatureValueDom.appendChild(signatureValueNode);

		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {
			// <ds:Object>
			if (params.isManifestSignature()) {

				Document doc = DomUtils.buildDOM(reference.getContents());
				Element root = doc.getDocumentElement();
				NodeList referencesNodes = root.getChildNodes();
				String idAttribute = root.getAttribute(XMLDSigAttribute.ID.getAttributeName());

				// rebuild manifest element to avoid namespace duplication
				final Element manifestDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.MANIFEST);	
				manifestDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), idAttribute);
				for (int i = 0; i < referencesNodes.getLength(); i++) {
					Node copyNode = documentDom.importNode(referencesNodes.item(i), true);
					manifestDom.appendChild(copyNode);
				}

				final Element dom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.OBJECT);
				dom.appendChild(manifestDom);
				signatureDom.appendChild(dom);
			} else if (params.isEmbedXML()) {
				Document doc = DomUtils.buildDOM(reference.getContents());
				Element root = doc.getDocumentElement();
				Node adopted = documentDom.adoptNode(root);

				final Element dom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.OBJECT);
				final String id = reference.getUri().substring(1);
				dom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), id);
				dom.appendChild(adopted);
				signatureDom.appendChild(dom);
			} else {
				final String base64EncodedOriginalDocument = Utils.toBase64(DSSUtils.toByteArray(reference.getContents()));
				final Element objectDom = DomUtils.addTextElement(documentDom, signatureDom, getXmldsigNamespace(), XMLDSigElement.OBJECT, base64EncodedOriginalDocument);
				final String id = reference.getUri().substring(1);
				objectDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), id);
			}
		}
		return createXmlDocument();
	}

}
