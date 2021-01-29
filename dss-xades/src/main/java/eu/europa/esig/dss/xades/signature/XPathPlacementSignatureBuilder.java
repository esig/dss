package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.w3c.dom.Node;

/**
 * This class creates signatures that are being enveloped into the parent document
 * based on the defined (if any) XPath location.
 *
 */
public abstract class XPathPlacementSignatureBuilder extends XAdESSignatureBuilder {

    /**
     * The default constructor for SignatureBuilder.
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

    @Override
    protected Node getParentNodeOfSignature() {
        final String xPathLocationString = params.getXPathLocationString();
        if (Utils.isStringNotEmpty(xPathLocationString)) {
            return DomUtils.getElement(documentDom, xPathLocationString);
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
