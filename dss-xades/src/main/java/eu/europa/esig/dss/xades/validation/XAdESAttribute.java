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

import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.xmldsig.definition.XMLDSigAttribute;
import eu.europa.esig.xmldsig.definition.XMLDSigPaths;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureAttribute;
import eu.europa.esig.dss.spi.x509.tsp.TimestampInclude;
import eu.europa.esig.xades.definition.XAdESPaths;
import eu.europa.esig.xades.definition.xades111.XAdES111Paths;
import eu.europa.esig.xades.definition.xades132.XAdES132Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Represents a XAdES attribute
 */
public class XAdESAttribute implements SignatureAttribute {
	
	private static final long serialVersionUID = 7860166312054634028L;

	private static final Logger LOG = LoggerFactory.getLogger(XAdESAttribute.class);

	/** The corresponding element */
	private final Element element;

	/** The XPath list to use */
	private final XAdESPaths xadesPaths;

	/** The tag name of the element */
	private String localName;

	/** Identifies the instance */
	private XAdESAttributeIdentifier identifier;

	/**
	 * Default constructor
	 *
	 * @param element {@link Element}
	 * @param xadesPaths {@link XAdESPaths}
	 */
	XAdESAttribute(Element element, XAdESPaths xadesPaths) {
		this.element = element;
		this.xadesPaths = xadesPaths;
	}
	
	/**
	 * Returns the local name of the element
	 * @return {@link String} attribute's name
	 */
	public String getName() {
		if (localName == null) {
			localName = element.getLocalName();
		}
		return localName;
	}
	
	/**
	 * Returns the current {@code Element}
	 * 
	 * @return {@link Element}
	 */
	public final Element getElement() {
		return element;
	}
	
	/**
	 * Returns namespace of the element
	 *
	 * @return {@link String} namespace
	 */
	public String getNamespace() {
		return element.getNamespaceURI();
	}
	
	/**
	 * Returns an inner {@link Element} found by the given {@code xPathExpression}
	 *
	 * @param xPathExpression {@link String} to find an element
	 * @return {@link Element}
	 */
	public final Element findElement(String xPathExpression) {
		return DomUtils.getElement(element, xPathExpression);
	}

	/**
	 * Returns a {@link NodeList} found by the given {@code xPathExpression}
	 *
	 * @param xPathExpression {@link String} to find an element
	 * @return {@link NodeList}
	 */
	public final NodeList getNodeList(String xPathExpression) {
		return DomUtils.getNodeList(element, xPathExpression);
	}

	/**
	 * Returns TimeStamp Canonicalization Method
	 *
	 * @return {@link String} timestamp canonicalization method
	 */
	public String getTimestampCanonicalizationMethod() {
		String canonicalizationMethod = DomUtils.getValue(element, XMLDSigPaths.CANONICALIZATION_ALGORITHM_PATH);
		if (Utils.isStringEmpty(canonicalizationMethod)) {
			NodeList nodeList = DomUtils.getNodeList(element, XAdES111Paths.HASH_DATA_INFO_TRANSFORM_PATH);
			if (nodeList != null && nodeList.getLength() == 1) {
				Element transform = (Element) nodeList.item(0);
				canonicalizationMethod = transform.getAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName());
			} else {
				LOG.warn("Unable to retrieve the canonicalization algorithm");
			}
		}
		return canonicalizationMethod;
	}
	
	/**
	 * Returns a list of {@link TimestampInclude}d references in case of IndividualDataObjectsTimestamp,
	 * NULL if does not contain any includes
	 *
	 * @return list of {@link TimestampInclude}s in case of IndividualDataObjectsTimestamp, NULL otherwise
	 */
	public List<TimestampInclude> getTimestampIncludedReferences() {
		String currentIncludePath = xadesPaths.getCurrentInclude();
		if (currentIncludePath != null) {
			final NodeList timestampIncludes = DomUtils.getNodeList(element, currentIncludePath);
			if (timestampIncludes != null && timestampIncludes.getLength() > 0) {
				List<TimestampInclude> includes = new ArrayList<>();
				for (int jj = 0; jj < timestampIncludes.getLength(); jj++) {
					final Element include = (Element) timestampIncludes.item(jj);
					final String uri = DomUtils.getId(include.getAttribute(XAdES132Attribute.URI.getAttributeName()));
					final String referencedData = include.getAttribute(XAdES132Attribute.REFERENCED_DATA.getAttributeName());
					includes.add(new TimestampInclude(uri, Boolean.parseBoolean(referencedData)));
				}
				return includes;
			}
		}
		return null;
	}

	/**
	 * Gets the attribute identifier
	 *
	 * @return {@link XAdESAttributeIdentifier}
	 */
	public XAdESAttributeIdentifier getIdentifier() {
		if (identifier == null) {
			identifier = XAdESAttributeIdentifier.build(element);
		}
		return identifier;
	}
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		XAdESAttribute that = (XAdESAttribute) o;

		return Objects.equals(this.getIdentifier(), that.getIdentifier());
	}

	@Override
	public int hashCode() {
		return identifier != null ? identifier.hashCode() : 0;
	}

	@Override
	public String toString() {
		return getName();
	}

}
