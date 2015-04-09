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

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.List;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.apache.xml.utils.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.MimeType;

/**
 * This class helps us home users to resolve http URIs without a network connection
 *
 *
 */
public class OfflineResolver extends ResourceResolverSpi {

	private static final Logger logger = LoggerFactory.getLogger(OfflineResolver.class);

	private final List<DSSDocument> documents;

	static {

		Init.init();
	}

	public OfflineResolver(final List<DSSDocument> documents) {

		this.documents = documents;
	}

	@Override
	public boolean engineCanResolveURI(final ResourceResolverContext context) {

		final Attr uriAttr = context.attr;
		final String baseUriString = context.baseUri;

		String documentUri = uriAttr.getNodeValue();
		documentUri = decodeUrl(documentUri);
		if (documentUri.equals("") || documentUri.startsWith("#")) {
			return false;
		}
		try {

			if (isKnown(documentUri) != null) {

				logger.debug("I state that I can resolve '" + documentUri.toString() + "' (external document)");
				return true;
			}
			final URI baseUri = new URI(baseUriString);
			URI uriNew = new URI(baseUri, documentUri);
			if (uriNew.getScheme().equals("http")) {

				logger.debug("I state that I can resolve '" + uriNew.toString() + "'");
				return true;
			}
			logger.debug("I state that I can't resolve '" + uriNew.toString() + "'");
		} catch (URI.MalformedURIException ex) {
			if (documents == null || documents.size() == 0) {
				logger.warn("OfflineResolver: WARNING: ", ex);
			}
		}
		if (doesContainOnlyOneDocument()) {

			return true;
		}
		return false;
	}

	private String decodeUrl(String documentUri) {
		try {
			return URLDecoder.decode(documentUri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			logger.error(e.getMessage(), e);
		}
		return documentUri;
	}

	@Override
	public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {

		final Attr uriAttr = context.attr;
		final String baseUriString = context.baseUri;
		String documentUri = uriAttr.getNodeValue();
		documentUri = decodeUrl(documentUri);
		final DSSDocument document = getDocument(documentUri);
		if (document != null) {

			// The input stream is closed automatically by XMLSignatureInput class

			// TODO-Bob (05/09/2014):  There is an error concerning the input streams base64 encoded. Some extra bytes are added within the santuario which breaks the HASH.
			// TODO-Vin (05/09/2014): Can you create an isolated test-case JIRA DSS-?
			InputStream inputStream = document.openStream();
			//			final byte[] bytes = DSSUtils.toByteArray(inputStream);
			//			final String string = new String(bytes);
			//			inputStream = DSSUtils.toInputStream(bytes);
			final XMLSignatureInput result = new XMLSignatureInput(inputStream);
			result.setSourceURI(documentUri);
			final MimeType mimeType = document.getMimeType();
			if (mimeType != null) {
				result.setMIMEType(mimeType.getMimeTypeString());
			}
			return result;
		} else {

			Object exArgs[] = {"The uriNodeValue " + documentUri + " is not configured for offline work"};
			throw new ResourceResolverException("generic.EmptyMessage", exArgs, documentUri, baseUriString);
		}
	}

	private DSSDocument isKnown(final String documentUri) {

		for (final DSSDocument dssDocument : documents) {

			if (isRightDocument(documentUri, dssDocument)) {

				return dssDocument;
			}
			DSSDocument nextDssDocument = dssDocument.getNextDocument();
			while (nextDssDocument != null) {

				if (isRightDocument(documentUri, nextDssDocument)) {
					return nextDssDocument;
				}
				nextDssDocument = nextDssDocument.getNextDocument();
			}
		}
		return null;
	}

	private static boolean isRightDocument(final String documentUri, final DSSDocument document) {

		final String documentUri_ = document.getName();
		if (documentUri.equals(documentUri_)) {

			return true;
		}
		final int length = documentUri.length();
		final int length_ = documentUri_.length();
		// For the file name as "/toto.txt"
		final boolean case1 = documentUri.startsWith("/") && length - 1 == length_;
		// For the file name as "./toto.txt"
		final boolean case2 = documentUri.startsWith("./") && length - 2 == length_;
		if (documentUri.endsWith(documentUri_) && (case1 || case2)) {

			return true;
		}
		return false;
	}

	private DSSDocument getDocument(final String documentUri) {

		final DSSDocument document = isKnown(documentUri);
		if (document != null) {
			return document;
		}
		if (doesContainOnlyOneDocument()) {

			return documents.get(0);
		}
		return null;
	}

	private boolean doesContainOnlyOneDocument() {

		return documents != null && documents.size() == 1;
	}
}