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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;

import java.util.List;

/**
 * Resolver for detached signature only.
 * The reference URI must be null or refer a specific file.
 *
 */
public class DetachedSignatureResolver extends ResourceResolverSpi {

	private static final Logger LOG = LoggerFactory.getLogger(DetachedSignatureResolver.class);

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
		DSSDocument document = getBestCandidate(context);
		if (document instanceof DigestDocument) {
			// requires pre-calculated base64-encoded digest
			return new DigestDocumentXMLSignatureInput((DigestDocument) document, digestAlgorithm);
		} else {
			return new DSSDocumentXMLSignatureInput(document);
		}
	}

	private DSSDocument getBestCandidate(ResourceResolverContext context) throws ResourceResolverException {
		if (definedFilename(context) && isDocumentNamesDefined()) {
			Attr uriAttr = context.attr;
			String uriValue = DSSUtils.decodeURI(uriAttr.getNodeValue());
			Digest referenceDigest = DSSXMLUtils.getDigestAndValue(uriAttr.getOwnerElement());

			DSSDocument bestCandidate = getBestCandidateByDigest(referenceDigest, uriValue);
			if (bestCandidate == null) {
				bestCandidate = getBestCandidateByName(uriValue);
			}
			if (bestCandidate != null) {
				return bestCandidate;
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

	private DSSDocument getBestCandidateByDigest(Digest referenceDigest, String uriValue) {
		if (referenceDigest == null) {
			return null;
		}
		DSSDocument bestCandidate = null;
		for (DSSDocument dssDocument : documents) {
			if (referenceDigest.equals(getDocumentDigest(referenceDigest.getAlgorithm(), dssDocument))) {
				if (bestCandidate != null) {
					LOG.warn("Multiple documents match the same reference with URI '{}'!", uriValue);
					if (!Utils.areStringsEqual(dssDocument.getName(), uriValue)) {
						// do not change the best candidate in case of name mismatch
						continue;
					}
				}
				bestCandidate = dssDocument;
			}
		}
		return bestCandidate;
	}

	private DSSDocument getBestCandidateByName(String uriValue) {
		if (uriValue == null) {
			return null;
		}
		DSSDocument bestCandidate = null;
		for (DSSDocument dssDocument : documents) {
			if (uriValue.equals(dssDocument.getName())) {
				if (bestCandidate != null) {
					LOG.warn("Multiple documents match the same reference with URI '{}'!", uriValue);
					break;
				}
				bestCandidate = dssDocument;
			}
		}
		return bestCandidate;
	}

	private Digest getDocumentDigest(DigestAlgorithm referenceDigestAlgorithm, DSSDocument document) {
		try {
			return DSSUtils.getDigest(referenceDigestAlgorithm, document);
		} catch (Exception e) {
			String errorMessage = "Unable to get digest for a document with name '{}' : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, document.getName(), e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, document.getName(), e.getMessage());
			}
			return new Digest();
		}
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
