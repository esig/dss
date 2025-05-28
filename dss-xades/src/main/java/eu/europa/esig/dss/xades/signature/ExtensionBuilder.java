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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentAnalyzer;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Builds XAdES signature extension
 */
public abstract class ExtensionBuilder extends XAdESBuilder {
	
	private static final Logger LOG = LoggerFactory.getLogger(ExtensionBuilder.class);

	/**
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
	 * The used document analyzer
	 */
	protected XMLDocumentAnalyzer documentAnalyzer;

	/**
	 * Empty constructor
	 */
	protected ExtensionBuilder() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param certificateVerifier {@code CertificateVerifier}
	 */
	protected ExtensionBuilder(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Initializes all variables to be used for signature extension
	 *
	 * @param signature {@link XAdESSignature}
	 * @return {@link XAdESSignature}
	 */
	protected XAdESSignature initializeSignatureBuilder(XAdESSignature signature) {
		xadesSignature = signature;
		currentSignatureDom = xadesSignature.getSignatureElement();

		xadesPath = xadesSignature.getXAdESPaths();

		// We ensure that all XML segments needed for the construction of the extension -T are present.
		// If a segment does not exist then it is created.
		ensureUnsignedProperties();
		ensureUnsignedSignatureProperties();
		ensureSignedDataObjectProperties();

		return xadesSignature;
	}

	/**
	 * Returns or creates (if it does not exist) the UnsignedPropertiesType DOM object.
	 */
	protected void ensureUnsignedProperties() {

		final NodeList qualifyingPropertiesNodeList = DomUtils.getNodeList(currentSignatureDom, xadesPath.getQualifyingPropertiesPath());
		if (qualifyingPropertiesNodeList.getLength() != 1) {
			throw new IllegalInputException("The signature does not contain QualifyingProperties element (or contains more than one)! Extension is not possible.");
		}

		qualifyingPropertiesDom = (Element) qualifyingPropertiesNodeList.item(0);

		final NodeList unsignedPropertiesNodeList = DomUtils.getNodeList(currentSignatureDom, xadesPath.getUnsignedPropertiesPath());
		final int length = unsignedPropertiesNodeList.getLength();
		if (length == 1) {
			unsignedPropertiesDom = (Element) unsignedPropertiesNodeList.item(0);
		} else if (length == 0) {
			unsignedPropertiesDom = DomUtils.addElement(documentDom, qualifyingPropertiesDom, getXadesNamespace(), getCurrentXAdESElements().getElementUnsignedProperties());
			if (params.isPrettyPrint()) {
				qualifyingPropertiesDom = (Element) DSSXMLUtils.alignChildrenIndents(qualifyingPropertiesDom);
				unsignedPropertiesDom = (Element) DomUtils.getNode(currentSignatureDom, xadesPath.getUnsignedPropertiesPath());
			}
		} else {
			throw new IllegalInputException("The signature contains more then one UnsignedProperties element! Extension is not possible.");
		}
	}

	/**
	 * Returns or creates (if it does not exist) the UnsignedSignaturePropertiesType DOM object.
	 */
	protected void ensureUnsignedSignatureProperties() {
		final NodeList unsignedSignaturePropertiesNodeList = DomUtils.getNodeList(currentSignatureDom, xadesPath.getUnsignedSignaturePropertiesPath());
		final int length = unsignedSignaturePropertiesNodeList.getLength();
		if (length == 1) {
			unsignedSignaturePropertiesDom = (Element) unsignedSignaturePropertiesNodeList.item(0);
		} else if (length == 0) {
			unsignedSignaturePropertiesDom = DomUtils.addElement(documentDom, unsignedPropertiesDom, getXadesNamespace(), getCurrentXAdESElements().getElementUnsignedSignatureProperties());
			if (params.isPrettyPrint()) {
				unsignedPropertiesDom = (Element) DSSXMLUtils.indentAndReplace(documentDom, unsignedPropertiesDom);
				unsignedSignaturePropertiesDom = (Element) DomUtils.getNode(currentSignatureDom, xadesPath.getUnsignedSignaturePropertiesPath());
			}
		} else {
			throw new IllegalInputException("The signature contains more than one UnsignedSignatureProperties element! Extension is not possible.");
		}
	}

	/**
	 * Returns or create (if it does not exist) the SignedDataObjectProperties DOM object.
	 */
	protected void ensureSignedDataObjectProperties() {
		final NodeList signedDataObjectPropertiesNodeList = DomUtils.getNodeList(currentSignatureDom, xadesPath.getSignedDataObjectPropertiesPath());
		final int length = signedDataObjectPropertiesNodeList.getLength();
		if (length > 1) {
			throw new IllegalInputException("The signature contains more than one SignedDataObjectProperties element! Extension is not possible.");
		}
	}

	/**
	 * Indents the {@code nodeToIndent} if pretty-print is enabled
	 *
	 * @param nodeToIndent {@link Element} to be indented
	 * @param oldNode {@link Element} the old node
	 * @return {@link Element}
	 */
	protected Element indentIfPrettyPrint(Element nodeToIndent, Element oldNode) {
		if (params.isPrettyPrint()) {
			nodeToIndent = (Element) DSSXMLUtils.indentAndExtend(documentDom, nodeToIndent, oldNode);
		}
		return nodeToIndent;
	}
	
	@Override
	protected void alignNodes() {
		if (unsignedSignaturePropertiesDom != null) {
			DSSXMLUtils.alignChildrenIndents(unsignedSignaturePropertiesDom);
		}
		if (qualifyingPropertiesDom != null) {
			DSSXMLUtils.alignChildrenIndents(qualifyingPropertiesDom);
		}
	}
	
	/**
	 * Removes the given {@code nodeToRemove} from its parent
	 *
	 * @param nodeToRemove {@link Node} to remove
	 * @return String of the next TEXT sibling of the removed node (can be NULL if the TEXT sibling does not exist)
	 */
	protected String removeNode(Node nodeToRemove) {
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

	/**
	 * This method returns the current used XMLDSig namespace. Try to determine from the signature, from the parameters or the default value
	 */
	@Override
	protected DSSNamespace getXmldsigNamespace() {
		DSSNamespace xmldsigNamespace = xadesSignature.getXmldSigNamespace();
		if (xmldsigNamespace == null) {
			LOG.warn("Current XMLDSig namespace not found in the signature");
			xmldsigNamespace = params.getXmldsigNamespace();
			if (xmldsigNamespace == null) {
				LOG.warn("Current XMLDSig namespace not found in the parameters (use the default XMLDSig)");
				xmldsigNamespace = XMLDSigNamespace.NS;
					
			}
		}
		return xmldsigNamespace;
	}

	/**
	 * This method returns the current used XAdES namespace. Try to determine from the signature, from the parameters or the default value
	 */
	@Override
	protected DSSNamespace getXadesNamespace() {
		DSSNamespace xadesNamespace = xadesSignature.getXadesNamespace();
		if (xadesNamespace == null) { 
			LOG.warn("Current XAdES namespace not found in the signature");
			xadesNamespace = params.getXadesNamespace();
			if (xadesNamespace == null) {
				LOG.warn("Current XAdES namespace not found in the parameters (use the default XAdES 1.3.2)");
				xadesNamespace = XAdESNamespace.XADES_132;
					
			}
		}
		return xadesNamespace;
	}

	/**
	 * This method verifies whether signature extension is possible as it does not contain evidence records
	 */
	protected void assertUnsignedPropertiesExtensionPossible(AdvancedSignature signature) {
		if (Utils.isCollectionNotEmpty(signature.getEmbeddedEvidenceRecords())) {
			throw new IllegalInputException("Signature extension is not possible. " +
					"The signature already contains en embedded evidence record.");
		}
	}

	/**
	 * Initializes the document analyzer and other signature properties
	 *
	 * @param document {@link DSSDocument} containing a signature
	 * @return {@link XMLDocumentAnalyzer}
	 */
	protected XMLDocumentAnalyzer initDocumentAnalyzer(DSSDocument document) {
		params = new XAdESSignatureParameters();

		documentAnalyzer = new XMLDocumentAnalyzer(document);
		documentDom = documentAnalyzer.getRootElement();

		return documentAnalyzer;
	}
	
}
