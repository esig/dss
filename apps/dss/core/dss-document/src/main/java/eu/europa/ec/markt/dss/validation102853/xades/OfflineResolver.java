/*
 * Copyright  1999-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package eu.europa.ec.markt.dss.validation102853.xades;

import java.io.InputStream;
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

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

/**
 * This class helps us home users to resolve http URIs without a network connection
 *
 * @author $Author$
 */
public class OfflineResolver extends ResourceResolverSpi {

	/**
	 * {@link org.apache.commons.logging} logging facility
	 */
	private static final Logger LOG = LoggerFactory.getLogger(OfflineResolver.class);

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
		if (documentUri.equals("") || documentUri.startsWith("#")) {
			return false;
		}
		try {

			if (isKnown(documentUri) != null) {

				LOG.debug("I state that I can resolve '" + documentUri.toString() + "' (external document)");
				return true;
			}
			final URI baseUri = new URI(baseUriString);
			URI uriNew = new URI(baseUri, documentUri);
			if (uriNew.getScheme().equals("http")) {

				LOG.debug("I state that I can resolve '" + uriNew.toString() + "'");
				return true;
			}
			LOG.debug("I state that I can't resolve '" + uriNew.toString() + "'");
		} catch (URI.MalformedURIException ex) {
			if (documents == null || documents.size() == 0) {
				LOG.warn("OfflineResolver: WARNING: ", ex);
			}
		}
		if (doesContainOnlyOneDocument()) {

			return true;
		}
		return false;
	}

	@Override
	public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {

		final Attr uriAttr = context.attr;
		final String baseUriString = context.baseUri;
		String uriNodeValue = uriAttr.getNodeValue();
		final DSSDocument document = getDocument(uriNodeValue);
		if (document != null) {

			// The input stream is closed automatically by XMLSignatureInput class

			// TODO-Bob (05/09/2014):  There is an error concerning the input streams base64 encoded. Some extra bytes are added within the santuario which breaks the HASH.
			// TODO-Vin (05/09/2014): Can you create an isolated test-case JIRA DSS-?
			InputStream inputStream = document.openStream();
			//			final byte[] bytes = DSSUtils.toByteArray(inputStream);
			//			final String string = new String(bytes);
			//			inputStream = DSSUtils.toInputStream(bytes);
			final XMLSignatureInput result = new XMLSignatureInput(inputStream);
			result.setSourceURI(uriNodeValue);
			final MimeType mimeType = document.getMimeType();
			if (mimeType != null) {
				result.setMIMEType(mimeType.getMimeTypeString());
			}
			return result;
		} else {

			Object exArgs[] = {"The uriNodeValue " + uriNodeValue + " is not configured for offline work"};
			throw new ResourceResolverException("generic.EmptyMessage", exArgs, uriNodeValue, baseUriString);
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