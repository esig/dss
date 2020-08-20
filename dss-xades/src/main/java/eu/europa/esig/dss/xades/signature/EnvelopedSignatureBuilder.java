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

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * This class handles the specifics of the enveloped XML signature
 *
 */
class EnvelopedSignatureBuilder extends XAdESSignatureBuilder {

	/**
	 * The default constructor for EnvelopedSignatureBuilder. The enveloped signature uses by default the exclusive
	 * method of canonicalization.
	 * 
	 * @param params
	 *            The set of parameters relating to the structure and process of the creation or extension of the
	 *            electronic signature.
	 * @param document
	 *            The original document to sign.
	 * @param certificateVerifier
	 */
	public EnvelopedSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument document, final CertificateVerifier certificateVerifier) {
		super(params, document, certificateVerifier);
	}

	/**
	 * In case of enveloped signature, the document should be the original file. Important for inclusive
	 * canonicalization and namespaces
	 */
	@Override
	protected Document buildRootDocumentDom() {
		return DomUtils.buildDOM(document);
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
