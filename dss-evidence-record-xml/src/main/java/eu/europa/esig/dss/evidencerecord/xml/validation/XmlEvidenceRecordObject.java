package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordObject;
import eu.europa.esig.dss.evidencerecord.common.validation.Orderable;
import org.w3c.dom.Element;

/**
 * Represents an element of Xml Evidence Record
 *
 */
public interface XmlEvidenceRecordObject extends EvidenceRecordObject, Orderable {

    /**
     * Gets the current Element corresponding to the object type
     *
     * @return {@link Element}
     */
    Element getElement();

}
