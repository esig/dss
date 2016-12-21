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

import java.net.URLEncoder;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * This class handles the specifics of the detached XML signature.
 */
class DetachedSignatureBuilder extends XAdESSignatureBuilder {

	private static final Logger logger = LoggerFactory.getLogger(DetachedSignatureBuilder.class);

	/**
	 * The default constructor for DetachedSignatureBuilder.<br>
	 * The detached signature uses by default the exclusive method of canonicalization.
	 * 
	 * @param params
	 *            The set of parameters relating to the structure and process of the creation or extension of the
	 *            electronic signature.
	 * @param origDoc
	 *            The original document to sign.
	 * @param certificateVerifier
	 */
	public DetachedSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument origDoc, final CertificateVerifier certificateVerifier) {
		super(params, origDoc, certificateVerifier);
		setCanonicalizationMethods(params, CanonicalizationMethod.EXCLUSIVE);
	}

	@Override
	protected Document buildRootDocumentDom() {
		if (params.getRootDocument() != null) {
			return params.getRootDocument();
		}
		return DomUtils.buildDOM();
	}

	@Override
	protected Node getParentNodeOfSignature() {
		if (params.getRootDocument() != null) {
			return documentDom.getDocumentElement();
		}
		return documentDom;
	}

	@Override
	protected DSSReference createReference(DSSDocument document, int referenceIndex) {
		final DSSReference reference = new DSSReference();
		reference.setId("r-id-" + referenceIndex);
		final String fileURI = document.getName() != null ? document.getName() : "";
		try {
			reference.setUri(URLEncoder.encode(fileURI, "UTF-8"));
		} catch (Exception e) {
			logger.warn("Unable to encode uri '" + fileURI + "' : " + e.getMessage());
			reference.setUri(fileURI);
		}
		reference.setContents(document);
		reference.setDigestMethodAlgorithm(params.getDigestAlgorithm());
		return reference;
	}

	@Override
	protected DSSDocument transformReference(final DSSReference reference) {
		return reference.getContents();
	}

}