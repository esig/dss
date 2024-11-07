/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AnyType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import org.w3c.dom.Element;

import jakarta.xml.bind.JAXBElement;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An abstract implementation of {@code OtherTSLPointerPredicate}
 *
 */
public abstract class AbstractOtherTSLPointerPredicate implements OtherTSLPointerPredicate {

	/**
	 * Default constructor
	 */
	protected AbstractOtherTSLPointerPredicate() {
	}

	/**
	 * Extracts the additional information map
	 *
	 * @param o {@link OtherTSLPointerType}
	 * @return a map of property names and values
	 */
	protected Map<String, Object> extractAdditionalInformation(OtherTSLPointerType o) {
		Map<String, Object> result = new HashMap<>();

		AdditionalInformationType additionalInformation = o.getAdditionalInformation();
		if (additionalInformation != null) {
			List<Serializable> textualInformationOrOtherInformation = additionalInformation.getTextualInformationOrOtherInformation();
			for (Serializable serializable : textualInformationOrOtherInformation) {
				if (serializable instanceof AnyType) {
					AnyType anyType = (AnyType) serializable;
					for (Object content : anyType.getContent()) {
						if (content instanceof Element) {
							Element element = (Element) content;
							result.put("{" + element.getNamespaceURI() + "}" + element.getLocalName(), element.getTextContent());
						} else if (content instanceof JAXBElement) {
							JAXBElement<?> jaxbElement = (JAXBElement<?>) content;
							result.put(jaxbElement.getName().toString(), jaxbElement.getValue());
						}
					}
				}
			}
		}

		return result;
	}

}
