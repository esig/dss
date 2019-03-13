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

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public abstract class ExtensionBuilder extends XAdESBuilder {

	/*
	 * This object allows to access DOM signature representation using XPATH
	 */
	protected XAdESSignature xadesSignature;

	/**
	 * This field represents the current signature being extended.
	 */
	protected Element currentSignatureDom;

	/**
	 * This field represents the signature qualifying properties
	 */
	protected Element qualifyingPropertiesDom;

	/**
	 * This field represents the unsigned properties
	 */
	protected Element unsignedPropertiesDom;

	/**
	 * This field contains unsigned signature properties
	 */
	protected Element unsignedSignaturePropertiesDom;

	/**
	 * This field represents the signed properties
	 */
	protected Element signedPropertiesDom;

	/**
	 * This field contains signed data object properties
	 */
	protected Element signedDataObjectPropertiesDom;

	protected ExtensionBuilder(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Returns or creates (if it does not exist) the UnsignedPropertiesType DOM object.
	 *
	 * @throws DSSException
	 */
	protected void ensureUnsignedProperties() {

		final NodeList qualifyingPropertiesNodeList = DomUtils.getNodeList(currentSignatureDom, xPathQueryHolder.XPATH_QUALIFYING_PROPERTIES);
		if (qualifyingPropertiesNodeList.getLength() != 1) {
			throw new DSSException("The signature does not contain QualifyingProperties element (or contains more than one)! Extension is not possible.");
		}

		qualifyingPropertiesDom = (Element) qualifyingPropertiesNodeList.item(0);

		final NodeList unsignedPropertiesNodeList = DomUtils.getNodeList(currentSignatureDom, xPathQueryHolder.XPATH_UNSIGNED_PROPERTIES);
		final int length = unsignedPropertiesNodeList.getLength();
		if (length == 1) {
			unsignedPropertiesDom = (Element) qualifyingPropertiesNodeList.item(0);
		} else if (length == 0) {
			unsignedPropertiesDom = DomUtils.addElement(documentDom, qualifyingPropertiesDom, XAdESNamespaces.XAdES, "xades:UnsignedProperties");
			if (params.isPrettyPrint()) {
				qualifyingPropertiesDom = (Element) DSSXMLUtils.alignChildrenIndents(qualifyingPropertiesDom);
				unsignedPropertiesDom = (Element) DomUtils.getNode(currentSignatureDom, xPathQueryHolder.XPATH_UNSIGNED_PROPERTIES);
			}
		} else {
			throw new DSSException("The signature contains more then one UnsignedProperties element! Extension is not possible.");
		}
	}

	/**
	 * Returns or creates (if it does not exist) the UnsignedSignaturePropertiesType DOM object.
	 *
	 * @throws DSSException
	 */
	protected void ensureUnsignedSignatureProperties() {
		final NodeList unsignedSignaturePropertiesNodeList = DomUtils.getNodeList(currentSignatureDom, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
		final int length = unsignedSignaturePropertiesNodeList.getLength();
		if (length == 1) {
			unsignedSignaturePropertiesDom = (Element) unsignedSignaturePropertiesNodeList.item(0);
		} else if (length == 0) {
			unsignedSignaturePropertiesDom = DomUtils.addElement(documentDom, unsignedPropertiesDom, XAdESNamespaces.XAdES,
					"xades:UnsignedSignatureProperties");
			if (params.isPrettyPrint()) {
				unsignedPropertiesDom = (Element) DSSXMLUtils.indentAndReplace(documentDom, unsignedPropertiesDom);
				unsignedSignaturePropertiesDom = (Element) DomUtils.getNode(currentSignatureDom, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
			}
		} else {
			throw new DSSException("The signature contains more then one UnsignedSignatureProperties element! Extension is not possible.");
		}
	}

	/**
	 * Returns or create (if it does not exist) the SignedDataObjectProperties DOM object.
	 *
	 * @throws DSSException
	 */
	protected void ensureSignedDataObjectProperties() {
		final NodeList signedDataObjectPropertiesNodeList = DomUtils.getNodeList(currentSignatureDom, xPathQueryHolder.XPATH_SIGNED_DATA_OBJECT_PROPERTIES);
		final int length = signedDataObjectPropertiesNodeList.getLength();
		if (length == 1) {
			signedDataObjectPropertiesDom = (Element) signedDataObjectPropertiesNodeList.item(0);
		} else if (length > 1) {
			throw new DSSException("The signature contains more than one SignedDataObjectProperties element! Extension is not possible.");
		}
	}

	protected void assertSignatureValid(final XAdESSignature xadesSignature) {
		SignatureCryptographicVerification signatureCryptographicVerification = xadesSignature.getSignatureCryptographicVerification();
		if (!signatureCryptographicVerification.isSignatureIntact()) {
			final String errorMessage = signatureCryptographicVerification.getErrorMessage();
			throw new DSSException("Cryptographic signature verification has failed" + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
		}
	}
	
	protected Element indentIfPrettyPrint(Element nodeToIndent, Element oldNode) {
		if (params.isPrettyPrint()) {
			nodeToIndent = (Element) DSSXMLUtils.indentAndExtend(documentDom, nodeToIndent, oldNode);
		}
		return nodeToIndent;
	}
	
	protected void alignNodes() {
		if (unsignedSignaturePropertiesDom != null) {
			DSSXMLUtils.alignChildrenIndents(unsignedSignaturePropertiesDom);
		}
		if (qualifyingPropertiesDom != null) {
			DSSXMLUtils.alignChildrenIndents(qualifyingPropertiesDom);
		}
	}
	
	/**
	 * Removes the given nodeToRemove from its parentNode
	 * @param parentNode owner {@link Node} of the nodeToRemove
	 * @param nodeToRemove {@link Node} to remove
	 * @return String of the next TEXT sibling of the removed node (can be NULL if the TEXT sibling does not exist)
	 */
	protected String removeChild(Node parentNode, Node nodeToRemove) {
		String text = null;
		if (nodeToRemove != null) {
			Node nextSibling = nodeToRemove.getNextSibling();
			if (nextSibling != null && Node.TEXT_NODE == nextSibling.getNodeType()) {
				text = nextSibling.getNodeValue();
				unsignedSignaturePropertiesDom.removeChild(nextSibling);
			}
			unsignedSignaturePropertiesDom.removeChild(nodeToRemove);
		}
		return text;
	}

}
