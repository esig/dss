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
package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSNamespace;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSPath;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xmlers.XMLEvidenceRecordFacade;
import eu.europa.esig.xmlers.jaxb.EvidenceRecordType;
import jakarta.xml.bind.JAXBException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Class for validation of an XML Evidence Record (RFC 6283)
 *
 */
public class XMLEvidenceRecordAnalyzer extends DefaultEvidenceRecordAnalyzer {

    /** The root element of the document to validate */
    private Element evidenceRecordElement;

    /**
     * The default constructor for XMLEvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public XMLEvidenceRecordAnalyzer(final DSSDocument document) {
        super(document);
        this.evidenceRecordElement = toEvidenceRecordElement(document);
    }

    /**
     * Empty constructor
     */
    XMLEvidenceRecordAnalyzer() {
        // empty
    }

    static {
        DomUtils.registerNamespace(XMLERSNamespace.XMLERS);
    }

    private Element toEvidenceRecordElement(DSSDocument document) {
        try {
            Document dom = DomUtils.buildDOM(document);
            return DomUtils.getElement(dom, XMLERSPath.EVIDENCE_RECORD_PATH);
        } catch (Exception e) {
            throw new IllegalInputException(String.format("An XML file is expected : %s", e.getMessage()), e);
        }
    }

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        return DomUtils.startsWithXmlPreamble(dssDocument) && canBuildEvidenceRecord(dssDocument);
    }

    private boolean canBuildEvidenceRecord(DSSDocument dssDocument) {
        try (InputStream is = dssDocument.openStream()) {
            EvidenceRecordType erObject = XMLEvidenceRecordFacade.newFacade().unmarshall(is, false);
            return erObject != null;
        } catch (IOException | JAXBException | XMLStreamException | SAXException e) {
            return false;
        }
    }

    /**
     * Returns the XML evidence record element
     *
     * @return {@link Element}
     */
    public Element getEvidenceRecordElement() {
        return evidenceRecordElement;
    }

    /**
     * Returns the root element of the validating document
     *
     * @return {@link Document}
     */
    public Document getRootElement() {
        return evidenceRecordElement.getOwnerDocument();
    }

    @Override
    protected EvidenceRecord buildEvidenceRecord() {
        if (evidenceRecordElement != null) {
            final XmlEvidenceRecord evidenceRecord = new XmlEvidenceRecord(evidenceRecordElement);
            evidenceRecord.setFilename(document.getName());
            evidenceRecord.setOrigin(evidenceRecordOrigin);
            evidenceRecord.setManifestFile(manifestFile);
            evidenceRecord.setDetachedContents(detachedContents);
            return evidenceRecord;
        }
        return null;
    }

    @Override
    public EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

}
