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

import java.util.List;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class helps us home users to resolve http URIs without a network connection
 *
 */
public class OfflineResolver extends ResourceResolverSpi {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineResolver.class);

	private final List<DSSDocument> documents;
	private final DigestAlgorithm digestAlgorithm;

	public OfflineResolver(final List<DSSDocument> documents, DigestAlgorithm digestAlgorithm) {
		this.documents = documents;
		this.digestAlgorithm = digestAlgorithm;
	}

	@Override
	public boolean engineCanResolveURI(final ResourceResolverContext context) {
		String documentUri = getDocumentUri(context.attr);

		if (documentUri.startsWith("#")) {
			return false;
		}

		DSSDocument document = getDocument(documentUri);
		boolean docNullAndUriNotDefined = (document == null) && !isUriDefined(context.attr); // ASiC
		boolean docNamesNotDefined = (document == null) && isDocumentNamesNotDefined();
		if ((docNullAndUriNotDefined || docNamesNotDefined) && isContainOnlyOneDocument()) {
			document = documents.get(0);
		}

		if (document != null) {
			LOG.debug("I state that I can resolve '{}' (external document)", documentUri);
			return true;
		} else {
			LOG.debug("I state that I cannot resolve '{}' (external document)", documentUri);
			return false;
		}

	}

	@Override
	public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
		String documentUri = getDocumentUri(context.attr);

		DSSDocument document = getDocument(documentUri);
		boolean docNullAndUriNotDefined = (document == null) && !isUriDefined(context.attr); // ASiC
		boolean docNamesNotDefined = (document == null) && isDocumentNamesNotDefined();
		if ((docNullAndUriNotDefined || docNamesNotDefined) && isContainOnlyOneDocument()) {
			document = documents.get(0);
		}

		if (document instanceof DigestDocument) {
			DigestDocument digestDoc = (DigestDocument) document;
			XMLSignatureInput result = new XMLSignatureInput(digestDoc.getDigest(digestAlgorithm));
			result.setSourceURI(documentUri);
			return result;
		} else if (document != null) {
			final XMLSignatureInput result = new XMLSignatureInput(document.openStream());
			result.setSourceURI(documentUri);
			final MimeType mimeType = document.getMimeType();
			if (mimeType != null) {
				result.setMIMEType(mimeType.getMimeTypeString());
			}
			return result;
		} else {
			Object[] exArgs = { "The uriNodeValue '" + documentUri + "' is not configured for offline work" };
			throw new ResourceResolverException("generic.EmptyMessage", exArgs, documentUri, context.baseUri);
		}
	}

	private boolean isUriDefined(Attr uriAttr) {
		return (uriAttr != null) && (Utils.isStringNotEmpty(uriAttr.getNodeValue()));
	}

	private String getDocumentUri(Attr uriAttr) {
		String documentUri = "";
		if (uriAttr != null) {
			documentUri = uriAttr.getNodeValue();
		}
		return DSSUtils.decodeUrl(documentUri);
	}

	private DSSDocument getDocument(final String documentUri) {
		if (Utils.isCollectionNotEmpty(documents)) {
			for (final DSSDocument dssDocument : documents) {
				if (isRightDocument(documentUri, dssDocument)) {
					return dssDocument;
				}
			}
		}
		return null;
	}

	private static boolean isRightDocument(final String documentUri, final DSSDocument document) {
		final String documentUri_ = document.getName();
		if (documentUri_ == null) {
			return false;
		}
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

	private boolean isDocumentNamesNotDefined() {
		if (Utils.isCollectionNotEmpty(documents)) {
			for (final DSSDocument dssDocument : documents) {
				if (Utils.isStringNotEmpty(dssDocument.getName())) {
					return false;
				}
			}
		}
		return true;
	}

	private boolean isContainOnlyOneDocument() {
		return documents != null && documents.size() == 1;
	}

}