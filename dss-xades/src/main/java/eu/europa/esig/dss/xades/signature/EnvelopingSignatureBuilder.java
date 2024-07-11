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
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSObject;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.List;

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
	 * @param document
	 *            The original document to sign.
	 * @param certificateVerifier
	 *            {@link CertificateVerifier}
	 */
	public EnvelopingSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument document,
									  final CertificateVerifier certificateVerifier) {
		super(params, document, certificateVerifier);
	}

	@Override
	protected void incorporateSignedObjects() {
		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {
			// <ds:Object>
			if (reference.getObject() != null) {
				incorporateObject(reference.getObject());

			} else if (params.isManifestSignature()) {

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

			} else {
				DSSObject object = new DSSObject();

				DSSDocument content;
				if (params.isEmbedXML()) {
					content = reference.getContents();
				} else {
					String base64EncodedOriginalDocument = Utils.toBase64(DSSUtils.toByteArray(reference.getContents()));
					content = new InMemoryDocument(base64EncodedOriginalDocument.getBytes());
				}
				object.setContent(content);
				object.setId(reference.getUri().substring(1));

				incorporateObject(object);
			}
		}
	}

}
