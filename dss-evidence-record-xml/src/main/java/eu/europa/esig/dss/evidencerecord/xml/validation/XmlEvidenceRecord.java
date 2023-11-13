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
package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordParser;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampSource;
import eu.europa.esig.dss.evidencerecord.xml.validation.timestamp.XMLEvidenceRecordTimestampSource;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xmlers.XMLEvidenceRecordUtils;
import org.w3c.dom.Element;

import javax.xml.transform.dom.DOMSource;
import java.util.List;

/**
 * XML Evidence Record implementations (RFC 6283)
 *
 */
public class XmlEvidenceRecord extends DefaultEvidenceRecord {

    /** The current signature element */
    private final Element evidenceRecordElement;

    /**
     * Default constructor to instantiate an XML Evidence Record from a root element
     *
     * @param evidenceRecordElement {@link Element} representing the 'ers:EvidenceRecord' element
     */
    public XmlEvidenceRecord(final Element evidenceRecordElement) {
        this.evidenceRecordElement = evidenceRecordElement;
    }

    /**
     * Gets the EvidenceRecord XML Element
     *
     * @return {@link Element}
     */
    public Element getEvidenceRecordElement() {
        return evidenceRecordElement;
    }

    @Override
    protected EvidenceRecordParser buildEvidenceRecordParser() {
        return new XmlEvidenceRecordParser(evidenceRecordElement);
    }

    @Override
    protected EvidenceRecordTimeStampSequenceVerifier buildCryptographicEvidenceRecordVerifier() {
        return new XmlEvidenceRecordTimeStampSequenceVerifier(this);
    }

    @Override
    protected EvidenceRecordTimestampSource<?> buildTimestampSource() {
        return new XMLEvidenceRecordTimestampSource(this);
    }

    @Override
    public List<String> validateStructure() {
        return XMLEvidenceRecordUtils.getInstance().validateAgainstXSD(new DOMSource(evidenceRecordElement));
    }

    @Override
    public EvidenceRecordTypeEnum getReferenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

    @Override
    public byte[] getEncoded() {
        return DomUtils.serializeNode(evidenceRecordElement);
    }

}
