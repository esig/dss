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
package eu.europa.esig.dss.asic.signature.asice;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.asic.ASiCNamespace;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public abstract class AbstractManifestBuilder {

	protected void addSigReference(final Document documentDom, final Element asicManifestDom, String uri, MimeType mimeType) {
		final Element sigReferenceDom = DomUtils.addElement(documentDom, asicManifestDom, ASiCNamespace.NS, ASiCNamespace.SIG_REFERENCE);
		sigReferenceDom.setAttribute("URI", uri);
		sigReferenceDom.setAttribute("MimeType", mimeType.getMimeTypeString());
	}

	protected void addDataObjectReference(final Document documentDom, final Element asicManifestDom, DSSDocument document, DigestAlgorithm digestAlgorithm) {
		final Element dataObjectReferenceDom = DomUtils.addElement(documentDom, asicManifestDom, ASiCNamespace.NS, ASiCNamespace.DATA_OBJECT_REFERENCE);
		dataObjectReferenceDom.setAttribute("URI", document.getName());

		MimeType mimeType = document.getMimeType();
		if (mimeType != null) {
			dataObjectReferenceDom.setAttribute("MimeType", mimeType.getMimeTypeString());
		}

		final Element digestMethodDom = DomUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestMethod");
		digestMethodDom.setAttribute("Algorithm", digestAlgorithm.getUri());

		final Element digestValueDom = DomUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestValue");
		final Text textNode = documentDom.createTextNode(document.getDigest(digestAlgorithm));
		digestValueDom.appendChild(textNode);
	}

}
