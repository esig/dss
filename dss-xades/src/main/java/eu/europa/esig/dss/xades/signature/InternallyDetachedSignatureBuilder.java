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

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.List;

/**
 * This class handles the specifics of the internally detached XML signature.
 *
 */
class InternallyDetachedSignatureBuilder extends XPathPlacementSignatureBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(InternallyDetachedSignatureBuilder.class);

	/** Defines the name of the root signature container element, if the root element is not provided */
	private static final String DEFAULT_SIGNATURE_CONTAINER_NAME = "internally-detached";

	/**
	 * The default constructor for InternallyDetachedSignatureBuilder.<br>
	 * The internally detached signature uses by default the exclusive method of
	 * canonicalization.
	 * 
	 * @param params
	 *                            The set of parameters relating to the structure
	 *                            and process of the creation or extension of the
	 *                            electronic signature.
	 * @param document
	 *                            The original document to sign.
	 * @param certificateVerifier
	 *                            {@link CertificateVerifier} to be used
	 */
	public InternallyDetachedSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument document,
											  final CertificateVerifier certificateVerifier) {
		super(params, document, certificateVerifier);
	}

	@Override
	protected Document buildRootDocumentDom() {
		if (params.getRootDocument() != null) {
			return params.getRootDocument();
		} else if (Utils.isStringNotEmpty(params.getXPathLocationString())) {
			return DomUtils.buildDOM(document);
		} else {
			return createDefaultContainer();
		}
	}

	private Document createDefaultContainer() {
		Document rootDocument = DomUtils.buildDOM();
		Element rootElement = rootDocument.createElement(DEFAULT_SIGNATURE_CONTAINER_NAME);
		rootDocument.appendChild(rootElement);
		return rootDocument;
	}

	@Override
	protected void incorporateFiles() {
		List<DSSReference> references = params.getReferences();
		for (DSSReference ref : references) {
			String elementId = DomUtils.getId(ref.getUri());
			// the content shall be added only when it is not yet present in the document
			if (DomUtils.getElementById(documentDom, elementId) == null) {
				Document doc = DomUtils.buildDOM(ref.getContents());
				Element root = doc.getDocumentElement();
				Node adopted = documentDom.importNode(root, true);
				documentDom.getDocumentElement().appendChild(adopted);

			} else {
				LOG.info("The element with Id '{}' is already present in the signing document! " +
						"The addition is skipped.", elementId);
			}
		}
	}

}
