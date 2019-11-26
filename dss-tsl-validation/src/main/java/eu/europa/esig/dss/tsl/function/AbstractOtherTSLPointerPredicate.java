package eu.europa.esig.dss.tsl.function;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import javax.xml.bind.JAXBElement;

import org.w3c.dom.Element;

import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AnyType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;

public abstract class AbstractOtherTSLPointerPredicate implements Predicate<OtherTSLPointerType> {

	protected Map<String, Object> extractAdditionalInformation(OtherTSLPointerType o) {
		Map<String, Object> result = new HashMap<String, Object>();

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
