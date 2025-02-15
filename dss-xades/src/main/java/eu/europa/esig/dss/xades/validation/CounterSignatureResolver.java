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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigPath;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 * Resolver for a counter signature only.
 * 
 * Used for a counter signature extension.
 */
public class CounterSignatureResolver extends ResourceResolverSpi {

	/** The counter signed SignatureValue document */
	private final DSSDocument document;

	/**
	 * Default constructor
	 *
	 * @param document {@link DSSDocument} counter signed SignatureValue
	 */
	public CounterSignatureResolver(DSSDocument document) {
		this.document = document;
	}

	@Override
	public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
		String uriValue = getURIValue(context);
		Node node = resolveNode(uriValue);
		
		if (node != null) {
			return createFromNode(node);
		}

		Object[] exArgs = { String.format("Unable to find a signed content by URI : '%s'", uriValue) };
		throw new ResourceResolverException("generic.EmptyMessage", exArgs, null, context.baseUri);
	}

	private XMLSignatureInput createFromNode(Node node) {
		final XMLSignatureInput result = new XMLSignatureInput(DomUtils.serializeNode(node));
		result.setMIMEType(MimeTypeEnum.XML.getMimeTypeString());
		return result;
	}
	
	private boolean isXPointerSlash(String uri) {
		return uri.equals("#xpointer(/)");
	}

	@Override
	public boolean engineCanResolveURI(ResourceResolverContext context) {
		String uriValue = getURIValue(context);
		return (DomUtils.isXPointerQuery(uriValue) || DomUtils.isElementReference(uriValue)) && resolveNode(uriValue) != null;
	}

	private String getURIValue(ResourceResolverContext context) {
		Attr uriAttr = context.attr;
		if (uriAttr == null) {
			return null;
		}
		return DSSUtils.decodeURI(uriAttr.getNodeValue());
	}
	
	private Node resolveNode(String uriValue) {
		if (uriValue == null) {
			return null;
		}

		Document documentDom = DomUtils.buildDOM(document);
		Node node = DomUtils.getNode(documentDom, XMLDSigPath.ALL_SIGNATURE_VALUES_PATH + DomUtils.getXPathByIdAttribute(uriValue));
		
		if (node == null && isXPointerSlash(uriValue) && XMLDSigElement.SIGNATURE_VALUE.getTagName().equals(documentDom.getLocalName())) {
			node = documentDom;
		} else if (node == null && DomUtils.isXPointerQuery(uriValue)) {
			String xPointerId = DomUtils.getXPointerId(uriValue);
			node = DomUtils.getNode(documentDom, XMLDSigPath.ALL_SIGNATURE_VALUES_PATH + DomUtils.getXPathByIdAttribute(xPointerId));
		}
		
		if (node != null) {
			return node;
		}
		
		return null;
	}

}
