package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordObject;
import org.w3c.dom.Element;

/**
 * Represents an element of Xml Evidence Record
 *
 */
public interface XmlEvidenceRecordObject extends EvidenceRecordObject {

    /**
     * Gets the current Element corresponding to the object type
     *
     * @return {@link Element}
     */
    Element getElement();

    /**
     * Gets Order attribute value of the corresponding element
     *
     * @return Order attribute value
     */
    int getOrder();


}
