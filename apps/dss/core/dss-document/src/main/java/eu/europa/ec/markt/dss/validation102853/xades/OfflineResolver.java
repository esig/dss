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

	private final String documentURI;

	private final DSSDocument document;

	static {

		Init.init();
	}

	public OfflineResolver(final DSSDocument document) {

		this.documentURI = (document != null) ? document.getName() : null;
		this.document = document;
	}

	@Override
	public boolean engineCanResolveURI(final ResourceResolverContext context) {

		final Attr uriAttr = context.attr;
		final String baseUriString = context.baseUri;

		String uriNodeValue = uriAttr.getNodeValue();
		if (uriNodeValue.equals("") || uriNodeValue.startsWith("#")) {
			return false;
		}
		try {

			if (uriNodeValue.equals(documentURI)) {

				LOG.debug("I state that I can resolve '" + uriNodeValue.toString() + "' (external document)");
				return true;
			}
			final URI baseUri = new URI(baseUriString);
			URI uriNew = new URI(baseUri, uriNodeValue);
			if (uriNew.getScheme().equals("http")) {

				LOG.debug("I state that I can resolve '" + uriNew.toString() + "'");
				return true;
			}
			LOG.debug("I state that I can't resolve '" + uriNew.toString() + "'");
		} catch (URI.MalformedURIException ex) {
			if (document == null) {
				LOG.warn("OfflineResolver: WARNING: ", ex);
			}
		}
		if (document != null) {

			return true;
		}
		return false;
	}

	@Override
	public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {

		final Attr uriAttr = context.attr;
		final String baseUriString = context.baseUri;
		String uriNodeValue = uriAttr.getNodeValue();
		if (uriNodeValue.equals(documentURI) || document != null) {

			// The input stream is closed automatically by XMLSignatureInput class
			final InputStream inputStream = document.openStream();
			final XMLSignatureInput result = new XMLSignatureInput(inputStream);
			result.setSourceURI(uriNodeValue);
			final MimeType mimeType = document.getMimeType();
			if (mimeType != null) {
				result.setMIMEType(mimeType.getCode());
			}
			return result;
		} else {

			Object exArgs[] = {"The uriNodeValue " + uriNodeValue + " is not configured for offline work"};
			throw new ResourceResolverException("generic.EmptyMessage", exArgs, uriAttr, baseUriString);
		}
	}
}