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
package eu.europa.esig.dss.xades.validation;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashSet;
import java.util.Set;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * An implementation of a resource resolver, which evaluates xpointer expressions.
 *
 *
 *         Adapted by
 *
 */
public class XPointerResourceResolver extends ResourceResolverSpi {

	private static Logger LOG = LoggerFactory.getLogger(XPointerResourceResolver.class);

	private static final String XP_OPEN = "xpointer(";

	private static final String XNS_OPEN = "xmlns(";

	private XPathFactory xPathFactory;

	private Node baseNode;

	public XPointerResourceResolver(Node baseNode) {

		this.xPathFactory = XPathFactory.newInstance();
		this.baseNode = baseNode;
	}

	@Override
	public boolean engineCanResolveURI(final ResourceResolverContext context) {

		final Attr uriAttr = context.attr;
		final String uri = uriAttr.getNodeValue();
		final boolean xPointerQuery = isXPointerQuery(uri, false);
		if (LOG.isDebugEnabled()) {

			LOG.debug("I state that I " + (xPointerQuery ? "can" : "cannot") + " resolve Uri/Base Uri:'" + uri + "/" + context.baseUri + "'");
		}
		return xPointerQuery;
	}

	/**
	 * Indicates if the given URI is an XPointer query.
	 *
	 * @param uriValue URI to be analysed
	 * @return true if it is an XPointer query
	 */
	public static boolean isXPointerQuery(String uriValue, final boolean strict) {

		if (uriValue.isEmpty() || uriValue.charAt(0) != '#') {
			return false;
		}

		final String decodedUri;
		try {

			decodedUri = URLDecoder.decode(uriValue, "utf-8");
		} catch (UnsupportedEncodingException e) {
			LOG.warn("utf-8 not a valid encoding", e);
			return false;
		}
		final String parts[] = decodedUri.substring(1).split("\\s");
		// plain ID reference.
		if (parts.length == 1 && !parts[0].startsWith(XNS_OPEN)) {
			return strict ? false : true;
		}
		int ii = 0;
		for (; ii < parts.length - 1; ++ii) {

			if (!parts[ii].endsWith(")") || !parts[ii].startsWith(XNS_OPEN)) {
				return false;
			}
		}
		if (!parts[ii].endsWith(")") || !parts[ii].startsWith(XP_OPEN)) {
			return false;
		}
		return true;
	}

	@Override
	public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {

		final Attr uriAttr = context.attr;
		final String baseUri = context.baseUri;

		String uriNodeValue = uriAttr.getNodeValue();

		if (uriNodeValue.charAt(0) != '#') {
			return null;
		}

		String xpURI;
		try {
			xpURI = URLDecoder.decode(uriNodeValue, "utf-8");
		} catch (UnsupportedEncodingException e) {
			LOG.warn("utf-8 not a valid encoding", e);
			return null;
		}

		String parts[] = xpURI.substring(1).split("\\s");

		int i = 0;

		DSigNamespaceContext nsContext = null;

		if (parts.length > 1) {
			nsContext = new DSigNamespaceContext();

			for (; i < parts.length - 1; ++i) {
				if (!parts[i].endsWith(")") || !parts[i].startsWith(XNS_OPEN)) {
					return null;
				}

				String mapping = parts[i].substring(XNS_OPEN.length(), parts[i].length() - 1);

				int pos = mapping.indexOf('=');

				if (pos <= 0 || pos >= mapping.length() - 1) {
					throw new ResourceResolverException("malformed namespace part of XPointer expression", uriNodeValue, baseUri);
				}

				nsContext.addNamespace(mapping.substring(0, pos), mapping.substring(pos + 1));
			}
		}

		try {
			Node node = null;
			NodeList nodes = null;

			// plain ID reference.
			if (i == 0 && !parts[i].startsWith(XP_OPEN)) {
				node = this.baseNode.getOwnerDocument().getElementById(parts[i]);
			} else {
				if (!parts[i].endsWith(")") || !parts[i].startsWith(XP_OPEN)) {
					return null;
				}

				XPath xp = this.xPathFactory.newXPath();

				if (nsContext != null) {
					xp.setNamespaceContext(nsContext);
				}

				nodes = (NodeList) xp.evaluate(parts[i].substring(XP_OPEN.length(), parts[i].length() - 1), this.baseNode, XPathConstants.NODESET);

				if (nodes.getLength() == 0) {
					return null;
				}
				if (nodes.getLength() == 1) {
					node = nodes.item(0);
				}
			}

			XMLSignatureInput result = null;

			if (node != null) {
				result = new XMLSignatureInput(node);
			} else if (nodes != null) {
				Set<Node> nodeSet = new HashSet<Node>(nodes.getLength());

				for (int j = 0; j < nodes.getLength(); ++j) {
					nodeSet.add(nodes.item(j));
				}

				result = new XMLSignatureInput(nodeSet);
			} else {
				return null;
			}

			result.setMIMEType("text/xml");
			result.setExcludeComments(true);
			result.setSourceURI((baseUri != null) ? baseUri.concat(uriNodeValue) : uriNodeValue);

			return result;

		} catch (XPathExpressionException e) {
			throw new ResourceResolverException("malformed XPath inside XPointer expression", e, uriNodeValue, baseUri);
		}
	}
}