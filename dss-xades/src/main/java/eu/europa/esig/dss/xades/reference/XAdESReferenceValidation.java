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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.validation.TransformsDescriptionBuilder;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.List;

/**
 * Contains information about a XAdES reference validation
 */
public class XAdESReferenceValidation extends ReferenceValidation {

	private static final long serialVersionUID = 2721340360134442005L;

	private static final Logger LOG = LoggerFactory.getLogger(XAdESReferenceValidation.class);

	/** The digest value of the original document, before applying transformations (if accessible) */
	private final Reference reference;
	/** For XAdES : reference id */
	private final String id;
	/** For XAdES : reference uri */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param reference {@link Reference}
	 */
	public XAdESReferenceValidation(Reference reference) {
		this.reference = reference;
		this.id = reference.getId();
		this.uri = DSSXMLUtils.getReferenceURI(reference);
	}

	/**
	 * Gets Id of the reference
	 *
	 * @return {@link String}
	 */
	public String getId() {
		return id;
	}

	/**
	 * Gets URI of the reference
	 *
	 * @return {@link String}
	 */
	public String getUri() {
		return uri;
	}
	/**
	 * Returns original bytes of the referenced document
	 *
	 * @return byte array
	 */
	public byte[] getOriginalContentBytes() {
		return DSSXMLUtils.getReferenceOriginalContentBytes(reference);
	}

	@Override
	public String getName() {
		if (Utils.isStringNotBlank(id)) {
			return id;
		} else if (Utils.isStringNotBlank(uri)) {
			return uri;
		}
		return Utils.EMPTY_STRING;
	}

	@Override
	public List<String> getTransformationNames() {
		if (transforms == null) {
			transforms = new ArrayList<>();
			try {
				Transforms referenceTransforms = reference.getTransforms();
				if (referenceTransforms != null) {
					Element transformsElement = referenceTransforms.getElement();
					TransformsDescriptionBuilder transformsDescriptionBuilder = new TransformsDescriptionBuilder(transformsElement);
					transforms = transformsDescriptionBuilder.build();
				}
			} catch (XMLSecurityException e) {
				LOG.warn("Unable to analyze trasnformations", e);
			}
		}
		return transforms;
	}

}
