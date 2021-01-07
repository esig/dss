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
import eu.europa.esig.dss.utils.Utils;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds a user-friendly description for the provided 'ds:Transforms' element
 *
 */
public class TransformsDescriptionBuilder {

	private static final Map<String, String> presentableTransformationNames = new HashMap<>();

	static {
		presentableTransformationNames.put(Transforms.TRANSFORM_ENVELOPED_SIGNATURE, "Enveloped Signature Transform");
		presentableTransformationNames.put(Transforms.TRANSFORM_BASE64_DECODE, "Base64 Decoding");

		presentableTransformationNames.put(Transforms.TRANSFORM_XPATH2FILTER, "XPath Filter 2.0 Transform");
		presentableTransformationNames.put(Transforms.TRANSFORM_XPATH, "XPath filtering");
		presentableTransformationNames.put(Transforms.TRANSFORM_XSLT, "XSLT Transform");

		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS, "Canonical XML 1.0 with Comments");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS, "Canonical XML 1.1 with Comments");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS, "Exclusive XML Canonicalization 1.0 with Comments");

		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, "Canonical XML 1.0 (omits comments)");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, "Canonical XML 1.1 (omits comments)");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS, "Exclusive Canonical XML (omits comments)");
	}

	/** ds:Transforms element */
	private final Element transforms;

	/**
	 * Default constructor
	 *
	 * @param transforms {@link Element} ds:Transforms
	 */
	public TransformsDescriptionBuilder(Element transforms) {
		this.transforms = transforms;
	}
	
	/**
	 * Builds a list of Strings describing the 'ds:Transforms' element
	 * Returns an empty list if transforms are not found or cannot be extracted
	 * 
	 * @return a list of {@link String}
	 */
	public List<String> build() {
		List<String> transformsList = new ArrayList<>();
		if (transforms != null) {
			NodeList transformChildNodes = transforms.getChildNodes();
			if (transformChildNodes != null && transformChildNodes.getLength() > 0) {
				for (int i = 0; i < transformChildNodes.getLength(); i++) {
					Node transformation = transformChildNodes.item(i);
					if (Node.ELEMENT_NODE == transformation.getNodeType()) {
						transformsList.add(buildTransformationName(transformation));
					}
				}
			}
		}
		return transformsList;
	}

	/**
	 * Returns a complete description string for the given transformation node
	 * @param transformation {@link Node} containing a single reference transformation information
	 * @return transformation description name
	 */
	private String buildTransformationName(Node transformation) {
		String algorithmUri = DomUtils.getValue(transformation, "@Algorithm");
		String algorithm = algorithmUri;
		if (presentableTransformationNames.containsKey(algorithmUri)) {
			algorithm = presentableTransformationNames.get(algorithmUri);
		}
		StringBuilder stringBuilder = new StringBuilder(algorithm);
		if (transformation.hasChildNodes()) {
			NodeList childNodes = transformation.getChildNodes();
			stringBuilder.append(" (");
			boolean hasValues = false;
			
			for (int ii = 0; ii < childNodes.getLength(); ii++) {
				Node parameterNode = childNodes.item(ii);
				if (Node.ELEMENT_NODE != parameterNode.getNodeType()) {
					continue;
				}

				// attach attribute values
				NamedNodeMap attributes = parameterNode.getAttributes();
				for (int jj = 0; jj < attributes.getLength(); jj++) {
					Node attribute = attributes.item(jj);
					String attrName = attribute.getLocalName();
					String attrValue = attribute.getNodeValue();
					if (algorithmUri.equals(attrValue)) {
						continue; // skip the case when the algorithm uri is defined in a child node
					}
					if (hasValues) {
						stringBuilder.append("; ");
					}
					stringBuilder.append(attrName).append(": ");
					stringBuilder.append(attrValue);
					hasValues = true;
				}
				
				// attach node value
				Node parameterValueNode = parameterNode.getFirstChild();
				if (parameterValueNode != null && Node.TEXT_NODE == parameterValueNode.getNodeType() &&
						Utils.isStringNotBlank(parameterValueNode.getTextContent())) {
					if (hasValues) {
						stringBuilder.append("; ");
					}
					stringBuilder.append(parameterNode.getLocalName()).append(": ");
					stringBuilder.append(parameterValueNode.getTextContent());
					hasValues = true;
				}
			}
			stringBuilder.append(")");
		}
		return stringBuilder.toString();
	}

}
