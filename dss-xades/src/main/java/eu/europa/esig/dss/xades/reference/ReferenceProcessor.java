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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.List;

/**
 * Contains methods for processing {@code eu.europa.esig.dss.xades.reference.DSSReference}
 */
public class ReferenceProcessor {

    private static final Logger LOG = LoggerFactory.getLogger(ReferenceProcessor.class);

    /** Signature parameters used on signature creation */
    private XAdESSignatureParameters signatureParameters;

    /**
     * Empty constructor (to be used for non-signature references, e.g. for a Manifest)
     */
    public ReferenceProcessor() {
    }

    /**
     * The constructor to be used for reference processing on signature creation
     *
     * @param signatureParameters {@link XAdESSignatureParameters}
     */
    public ReferenceProcessor(XAdESSignatureParameters signatureParameters) {
        this.signatureParameters = signatureParameters;
    }

    /**
     * Returns an output content after processing the given {@code DSSReference}
     *
     * @param reference {@link DSSReference} to process
     * @return {@link DSSDocument} reference output content
     */
    public DSSDocument getReferenceOutput(DSSReference reference) {
        if (reference.getContents() instanceof DigestDocument) {
            return reference.getContents();
        }

        Node nodeToTransform = dereferenceNode(reference);
        if (nodeToTransform == null) {
            return reference.getContents();
        }
        List<DSSTransform> transforms = reference.getTransforms();
        if (isUniqueBase64Transform(transforms)) {
            return reference.getContents();
        }

        byte[] referenceOutputResult = DSSXMLUtils.applyTransforms(nodeToTransform, reference.getTransforms());

        if (ReferenceOutputType.NODE_SET.equals(DSSXMLUtils.getReferenceOutputType(reference)) && DomUtils.isDOM(referenceOutputResult)) {
            referenceOutputResult = DSSXMLUtils.canonicalize(DSSXMLUtils.DEFAULT_XMLDSIG_C14N_METHOD, referenceOutputResult);
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("Reference output : ");
            LOG.trace(new String(referenceOutputResult));
        }
        return new InMemoryDocument(referenceOutputResult);
    }

    private Node dereferenceNode(DSSReference reference) {
        Node deReferencedNode = getNodeToTransform(reference);
        if (deReferencedNode != null && DSSXMLUtils.isSameDocumentReference(reference.getUri())) {
            deReferencedNode = DomUtils.excludeComments(deReferencedNode);
        }
        return deReferencedNode;
    }

    private Node getNodeToTransform(DSSReference reference) {
        DSSDocument contents = reference.getContents();
        if (!DomUtils.isDOM(contents)) {
            // cannot be transformed
            return null;
        }

        String uri = reference.getUri();

        if (signatureParameters != null && signatureParameters.isEmbedXML()) {
            Document doc = DomUtils.buildDOM(contents);
            Element root = doc.getDocumentElement();

            Document doc2 = DomUtils.buildDOM();
            final Element dom = DomUtils.createElementNS(doc2, signatureParameters.getXmldsigNamespace(), XMLDSigElement.OBJECT);
            final Element dom2 = DomUtils.createElementNS(doc2, signatureParameters.getXmldsigNamespace(), XMLDSigElement.OBJECT);
            doc2.appendChild(dom2);
            dom2.appendChild(dom);
            dom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), DomUtils.getId(uri));

            Node adopted = doc2.adoptNode(root);
            dom.appendChild(adopted);
            return dom;

        } else if (!Utils.isStringBlank(uri) && uri.startsWith("#")) {
            final Document document = DomUtils.buildDOM(contents);
            DSSXMLUtils.recursiveIdBrowse(document.getDocumentElement());
            final String targetId = DomUtils.getId(uri);
            Element elementById = document.getElementById(targetId);
            if (elementById != null) {
                return elementById;
            }

        }

        if (Utils.isCollectionNotEmpty(reference.getTransforms())) {
            return DomUtils.buildDOM(contents);
        }

        return null;

    }

    private boolean isUniqueBase64Transform(List<DSSTransform> transforms) {
        return transforms != null && transforms.size() == 1 && transforms.get(0) instanceof Base64Transform;
    }

    /**
     * This method incorporates a list of references within the provided {@code referenceContainer} element
     *
     * @param referenceContainer
     *            the {@link Element} to incorporate a list of ds:Reference(s) within
     * @param references
     *            the list of {@link DSSReference}s to be incorporates
     * @param namespace
     *            the {@link DSSNamespace} to be used
     */
    public void incorporateReferences(Element referenceContainer, List<DSSReference> references, DSSNamespace namespace) {
        if (Utils.isCollectionNotEmpty(references)) {
            Document documentDom = referenceContainer.getOwnerDocument();
            for (DSSReference dssReference : references) {
                final Element referenceDom = DomUtils.createElementNS(documentDom, namespace, XMLDSigElement.REFERENCE);
                referenceContainer.appendChild(referenceDom);

                if (dssReference.getId() != null) {
                    referenceDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), dssReference.getId());
                }
                final String uri = dssReference.getUri();
                if (uri != null) {
                    referenceDom.setAttribute(XMLDSigAttribute.URI.getAttributeName(), uri);
                }
                final String referenceType = dssReference.getType();
                if (referenceType != null) {
                    referenceDom.setAttribute(XMLDSigAttribute.TYPE.getAttributeName(), referenceType);
                }

                DSSXMLUtils.incorporateTransforms(referenceDom, dssReference.getTransforms(), namespace);
                DSSXMLUtils.incorporateDigestMethod(referenceDom, dssReference.getDigestMethodAlgorithm(), namespace);

                DSSDocument documentAfterTransforms = getReferenceOutput(dssReference);
                String base64EncodedDigestBytes = documentAfterTransforms.getDigest(dssReference.getDigestMethodAlgorithm());
                DSSXMLUtils.incorporateDigestValue(referenceDom, base64EncodedDigestBytes, namespace);
            }
        }
    }

}
