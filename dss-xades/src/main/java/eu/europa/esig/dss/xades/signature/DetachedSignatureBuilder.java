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

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * This class handles the specifics of the detached XML signature.
 */
class DetachedSignatureBuilder extends XAdESSignatureBuilder {

	/**
	 * The default constructor for DetachedSignatureBuilder.<br>
	 * The detached signature uses by default the exclusive method of canonicalization.
	 * 
	 * @param params
	 *            The set of parameters relating to the structure and process of the creation or extension of the
	 *            electronic signature.
	 * @param document
	 *            The original document to sign.
	 * @param certificateVerifier
	 *            {@link CertificateVerifier}
	 */
	public DetachedSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument document,
									final CertificateVerifier certificateVerifier) {
		super(params, document, certificateVerifier);
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

}
