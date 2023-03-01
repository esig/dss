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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Attr;

import java.util.List;

/**
 * Resolver for detached signature only.
 * 
 * The reference URI must be null or refer a specific file.
 */
public class DetachedSignatureResolver extends ResourceResolverSpi {

	/** Detached documents */
	private final List<DSSDocument> documents;

	/** The DigestAlgorithm to use */
	private final DigestAlgorithm digestAlgorithm;

	/**
	 * Default constructor
	 *
	 * @param documents a list of {@link DSSDocument} detached documents
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 */
	public DetachedSignatureResolver(final List<DSSDocument> documents, DigestAlgorithm digestAlgorithm) {
		this.documents = documents;
		this.digestAlgorithm = digestAlgorithm;
	}

	@Override
	public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
		DSSDocument document = getCurrentDocument(context);
		if (document instanceof DigestDocument) {
			DigestDocument digestDoc = (DigestDocument) document;
			return new XMLSignatureInput(digestDoc.getDigest(digestAlgorithm));
		} else {
			return createFromCommonDocument(document);
		}
	}

	private XMLSignatureInput createFromCommonDocument(DSSDocument document) {
		// Full binaries are required
		final XMLSignatureInput result = new XMLSignatureInput(DSSUtils.toByteArray(document));
		final MimeType mimeType = document.getMimeType();
		if (mimeType != null) {
			result.setMIMEType(mimeType.getMimeTypeString());
		}
		return result;
	}

	private DSSDocument getCurrentDocument(ResourceResolverContext context) throws ResourceResolverException {
		if (definedFilename(context) && isDocumentNamesDefined()) {
			Attr uriAttr = context.attr;
			String uriValue = DSSUtils.decodeURI(uriAttr.getNodeValue());
			for (DSSDocument dssDocument : documents) {
				if (Utils.areStringsEqual(dssDocument.getName(), uriValue)) {
					return dssDocument;
				}
			}
			Object[] exArgs = { "Unable to find document '" + uriValue + "' (detached signature)" };
			throw new ResourceResolverException("generic.EmptyMessage", exArgs, uriValue, context.baseUri);
		}

		if (Utils.collectionSize(documents) == 1) {
			return documents.get(0);
		}

		Object[] exArgs = { "Unable to find document (detached signature)" };
		throw new ResourceResolverException("generic.EmptyMessage", exArgs, null, context.baseUri);

	}

	@Override
	public boolean engineCanResolveURI(ResourceResolverContext context) {
		return (nullURI(context) || definedFilename(context));
	}

	private boolean nullURI(ResourceResolverContext context) {
		return context.attr == null;
	}

	private boolean definedFilename(ResourceResolverContext context) {
		Attr uriAttr = context.attr;
		return uriAttr != null && Utils.isStringNotBlank(uriAttr.getNodeValue()) && !DomUtils.startsFromHash(uriAttr.getNodeValue());
	}

	private boolean isDocumentNamesDefined() {
		if (Utils.isCollectionNotEmpty(documents)) {
			for (final DSSDocument dssDocument : documents) {
				if (dssDocument.getName() != null) {
					return true;
				}
			}
		}
		return false;
	}

}
