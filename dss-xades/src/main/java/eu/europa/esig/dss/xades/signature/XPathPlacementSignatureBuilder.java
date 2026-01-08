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
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigPath;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.xpath.JavaXmlXPathQueryExecutor;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * This class creates signatures that are being enveloped into the parent document
 * based on the defined (if any) XPath location.
 *
 */
public abstract class XPathPlacementSignatureBuilder extends XAdESSignatureBuilder {

    /**
     * The default constructor for XPathPlacementSignatureBuilder for a document signing
     *
     * @param params              The set of parameters relating to the structure and process of the creation or extension of the
     *                            electronic signature.
     * @param document            The original document to sign.
     * @param certificateVerifier {@link CertificateVerifier}
     */
    protected XPathPlacementSignatureBuilder(XAdESSignatureParameters params, DSSDocument document,
                                             CertificateVerifier certificateVerifier) {
        super(params, document, certificateVerifier);
    }

    /**
     * The constructor for XPathPlacementSignatureBuilder for multiple documents signing
     *
     * @param params              The set of parameters relating to the structure and process of the creation or extension of the
     *                            electronic signature.
     * @param documents           The original documents to sign.
     * @param certificateVerifier {@link CertificateVerifier}
     */
    protected XPathPlacementSignatureBuilder(XAdESSignatureParameters params, List<DSSDocument> documents,
                                             CertificateVerifier certificateVerifier) {
        super(params, documents, certificateVerifier);
    }

    /**
     * This method verifies the conformance of the original document for an enveloped signature creation
     */
    protected void assertOriginalXmlDocumentValid() {
        if (Utils.collectionSize(documents) > 1) {
            throw new IllegalArgumentException(String.format("Only one original document is allowed for '%s' signature packaging!", params.getSignaturePackaging()));
        }
        if (!DomUtils.isDOM(documents.get(0))) {
            throw new IllegalInputException("Enveloped signature cannot be created. Reason : the provided document is not XML!");
        }

        initRootDocumentDom();

        final NodeList signatureNodeList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(documentDom);
        if (signatureNodeList == null || signatureNodeList.getLength() == 0) {
            return;
        }

        final Node parentSignatureNode = getParentNodeOfSignature();
        final Set<Node> parentNodes = getParentNodesChain(parentSignatureNode);

        for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {
            final Node signatureNode = signatureNodeList.item(ii);
            NodeList referenceNodeList = DSSXMLUtils.getReferenceNodeList(signatureNode);
            if (referenceNodeList == null || referenceNodeList.getLength() == 0) {
                continue;
            }

            for (int jj = 0; jj < referenceNodeList.getLength(); jj++) {
                final Node referenceNode = referenceNodeList.item(jj);
                if (isSignatureCoveredNodeAffected(referenceNode, parentNodes)) {
                    assertDoesNotContainEnvelopedTransform(referenceNode);
                }
            }
        }

    }

    private Set<Node> getParentNodesChain(Node node) {
        final Set<Node> nodesChain = new LinkedHashSet<>();
        nodesChain.add(node);
        for (Node parentNode = node.getParentNode(); parentNode != null; parentNode = parentNode.getParentNode()) {
            nodesChain.add(parentNode);
        }
        return nodesChain;
    }

    private boolean isSignatureCoveredNodeAffected(Node referenceNode, Set<Node> affectedNodes) {
        final String id = DSSXMLUtils.getAttribute(referenceNode, XMLDSigAttribute.URI.getAttributeName());
        if (id == null) {
            return false;
        } else if (Utils.isStringEmpty(id)) {
            // covers the whole file
            return true;
        } else {
            Node referencedNode = DomUtils.getElementById(documentDom, id);
            return affectedNodes.contains(referencedNode);
        }
    }

    private void assertDoesNotContainEnvelopedTransform(final Node referenceNode) {
        NodeList transformList = DomUtils.getNodeList(referenceNode, XMLDSigPath.TRANSFORMS_TRANSFORM_PATH);
        if (transformList != null && transformList.getLength() > 0) {
            for (int jj = 0; jj < transformList.getLength(); jj++) {
                final Element transformElement = (Element) transformList.item(jj);
                String transformAlgorithm = transformElement
                        .getAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName());
                if (Transforms.TRANSFORM_ENVELOPED_SIGNATURE.equals(transformAlgorithm)) {
                    throw new IllegalInputException(String.format(
                            "The parallel signature is not possible! The provided file contains a signature with an '%s' transform.",
                            Transforms.TRANSFORM_ENVELOPED_SIGNATURE));
                }
            }
        }
    }

    @Override
    protected Node getParentNodeOfSignature() {
        final String xPathLocationString = params.getXPathLocationString();
        if (Utils.isStringNotEmpty(xPathLocationString)) {
            NodeList nodeList = new JavaXmlXPathQueryExecutor().getNodeList(documentDom, xPathLocationString);
            if (nodeList != null && nodeList.getLength() == 1) {
                return nodeList.item(0);
            }
            throw new IllegalArgumentException(String.format(
                    "Unable to find an element corresponding to XPath location '%s'", xPathLocationString));
        }
        return documentDom.getDocumentElement();
    }

    @Override
    protected void incorporateSignatureDom(Node parentNodeOfSignature) {
        if (params.getXPathElementPlacement() == null || Utils.isStringEmpty(params.getXPathLocationString())) {
            super.incorporateSignatureDom(parentNodeOfSignature);
            return;
        }

        switch (params.getXPathElementPlacement()) {
            case XPathAfter:
                // root element referenced by XPath
                if (parentNodeOfSignature.isEqualNode(documentDom.getDocumentElement())) {
                    // append signature at end of document
                    parentNodeOfSignature.appendChild(signatureDom);

                } else {
                    // insert signature before next sibling or as last child
                    // if no sibling exists
                    Node parent = parentNodeOfSignature.getParentNode();
                    parent.insertBefore(signatureDom, parentNodeOfSignature.getNextSibling());
                }

                break;
            case XPathFirstChildOf:
                parentNodeOfSignature.insertBefore(signatureDom, parentNodeOfSignature.getFirstChild());
                break;
            default:
                parentNodeOfSignature.appendChild(signatureDom);
                break;
        }
    }

}
