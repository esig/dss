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

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xmlers.jaxb.EvidenceRecordType;
import eu.europa.esig.xmlers.XMLEvidenceRecordFacade;
import eu.europa.esig.xmlers.definition.XMLERSNamespace;
import eu.europa.esig.xmlers.definition.XMLERSPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import jakarta.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Class for validation of an XML Evidence Record (RFC 6283)
 *
 */
public class XMLEvidenceRecordValidator extends EvidenceRecordValidator {

    private static final Logger LOG = LoggerFactory.getLogger(XMLEvidenceRecordValidator.class);

    /** The root element of the document to validate */
    private Document rootElement;

    /**
     * The default constructor for XMLEvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public XMLEvidenceRecordValidator(final DSSDocument document) {
        super(document);
        this.rootElement = toDomDocument(document);
    }

    /**
     * Empty constructor
     */
    XMLEvidenceRecordValidator() {
        // empty
    }

    static {
        DomUtils.registerNamespace(XMLERSNamespace.XMLERS);
    }

    private Document toDomDocument(DSSDocument document) {
        try {
            return DomUtils.buildDOM(document);
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
     * Returns the root element of the validating document
     *
     * @return {@link Document}
     */
    public Document getRootElement() {
        return rootElement;
    }

    @Override
    protected EvidenceRecord buildEvidenceRecord() {
        Element evidenceRecordRootElement = getEvidenceRecordRootElement();
        if (evidenceRecordRootElement != null) {
            final XmlEvidenceRecord evidenceRecord = new XmlEvidenceRecord(evidenceRecordRootElement);
            evidenceRecord.setFilename(document.getName());
            evidenceRecord.setManifestFile(manifestFile);
            evidenceRecord.setDetachedContents(detachedContents);
            return evidenceRecord;
        }
        return null;
    }

    private Element getEvidenceRecordRootElement() {
        try {
            return DomUtils.getElement(rootElement, XMLERSPath.EVIDENCE_RECORD_PATH);
        } catch (Exception e) {
            LOG.warn("Unable to analyze manifest file '{}' : {}", document.getName(), e.getMessage());
            return null;
        }
    }


}
