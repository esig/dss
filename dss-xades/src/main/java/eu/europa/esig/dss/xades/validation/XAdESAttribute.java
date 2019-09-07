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

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.validation.ISignatureAttribute;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.xades.definition.XAdESPaths;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.definition.xmldsig.XMLDSigPaths;

public class XAdESAttribute implements ISignatureAttribute {
	
	private final Element element;
	private final XAdESPaths xadesPaths;
	
	private String localName;
	
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
	 * Returns namespae of the element
	 * @return {@link String} namespace
	 */
	public String getNamespace() {
		return element.getNamespaceURI();
	}
	
	/**
	 * Returns an inner {@link Element} found by the given {@code xPathExpression}
	 * @param xPathExpression {@link String} to find an element
	 */
	public final Element findElement(String xPathExpression) {
		return DomUtils.getElement(element, xPathExpression);
	}

	/**
	 * Returns a {@link NodeList} found by the given {@code xPathExpression}
	 * @param xPathExpression {@link String} to find an element
	 */
	public final NodeList getNodeList(String xPathExpression) {
		return DomUtils.getNodeList(element, xPathExpression);
	}

	/**
	 * Returns TimeStamp Canonicalization Method
	 * @return {@link String} timestamp canonicalization mathod
	 */
	public String getTimestampCanonicalizationMethod() {
		return DomUtils.getValue(element, XMLDSigPaths.CANONICALIZATION_ALGORITHM_PATH);
	}
	
	/**
	 * Returns a list of {@link TimestampInclude}d refereces in case of IndividualDataObjectsTimestamp,
	 * NULL if does not contain any includes
	 * @return list of {@link TimestampInclude}s in case of IndividualDataObjectsTimestamp, NULL otherwise
	 */
	public List<TimestampInclude> getTimestampIncludedReferences() {
		String currentIncludePath = xadesPaths.getCurrentInclude();
		if (currentIncludePath != null) {
			final NodeList timestampIncludes = DomUtils.getNodeList(element, currentIncludePath);
			if (timestampIncludes != null && timestampIncludes.getLength() > 0) {
				List<TimestampInclude> includes = new ArrayList<TimestampInclude>();
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
	
	public int getElementHashCode() {
		return element.hashCode();
	}
	
	@Override
	public String toString() {
		return getName();
	}

}
