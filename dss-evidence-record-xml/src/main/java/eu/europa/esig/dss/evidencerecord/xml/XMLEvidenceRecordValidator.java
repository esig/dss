package eu.europa.esig.dss.evidencerecord.xml;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.evidencerecord.common.EvidenceRecordValidator;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecord;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlEvidenceRecord;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.jaxb.common.definition.DSSNamespace;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.xmlers.definition.XMLERSElement;
import eu.europa.esig.xmlers.definition.XMLERSNamespaces;
import eu.europa.esig.xmlers.definition.XMLERSPaths;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class XMLEvidenceRecordValidator extends EvidenceRecordValidator {

    private static final Logger LOG = LoggerFactory.getLogger(XMLEvidenceRecordValidator.class);

    /** The root element of the document to validate */
    private Document rootElement;

    /** The XMLERS namespace */
    private DSSNamespace xmlersNamespace;

    /**
     * The default constructor for XMLEvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public XMLEvidenceRecordValidator(final DSSDocument document) {
        super(document);
        this.rootElement = toDomDocument(document);
        //initialiseSettings();
    }

    /**
     * Empty constructor
     */
    XMLEvidenceRecordValidator() {
        // empty
    }

    static {
        DomUtils.registerNamespace(XMLERSNamespaces.XMLERS);
    }

    private Document toDomDocument(DSSDocument document) {
        try {
            return DomUtils.buildDOM(document);
        } catch (Exception e) {
            throw new IllegalInputException(String.format("An XML file is expected : %s", e.getMessage()), e);
        }
    }

    /**
     * This method is called when creating a new instance of the {@code EvidenceRecord} with unknown schema.
     */
    private void initialiseSettings() {
        //recursiveNamespaceBrowser(rootElement);
    }

    /**
     * This method sets the namespace which will determinate the XMLERS Namespace to use.
     *
     * @param element {@link Element}
     */
    public void recursiveNamespaceBrowser(final Element element) {
        for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {
            final Node node = element.getChildNodes().item(ii);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                final String prefix = node.getPrefix();
                final Element childElement = (Element) node;
                final String namespaceURI = childElement.getNamespaceURI();
                final String localName = childElement.getLocalName();
                if (XMLERSElement.EVIDENCE_RECORD.isSameTagName(localName) && XMLERSElement.EVIDENCE_RECORD.getURI().equals(namespaceURI)) {
                    xmlersNamespace = new DSSNamespace(namespaceURI, prefix);
                    return;
                }
                recursiveNamespaceBrowser(childElement);
            }
        }
    }

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        return DomUtils.startsWithXmlPreamble(dssDocument);
    }

    @Override
    public Reports validateDocument() {
        // TODO : to be implemented
        return null;
    }

    /**
     * Returns the root element of the validating document
     *
     * @return {@link Document}
     */
    public Document getRootElement() {
        return rootElement;
    }

    /**
     * Returns an evidence record extracted from the document
     *
     * @return {@link EvidenceRecord}
     */
    public EvidenceRecord getEvidenceRecord() {
        Element evidenceRecordRootElement = getEvidenceRecordRootElement();
        if (evidenceRecordRootElement != null) {
            final XmlEvidenceRecord evidenceRecord = new XmlEvidenceRecord(evidenceRecordRootElement);
            evidenceRecord.setFilename(document.getName());
            evidenceRecord.setDetachedContents(detachedContents);
            return evidenceRecord;
        }
        return null;
    }

    private Element getEvidenceRecordRootElement() {
        try {
            return DomUtils.getElement(rootElement, XMLERSPaths.EVIDENCE_RECORD_PATH);
        } catch (Exception e) {
            LOG.warn("Unable to analyze manifest file '{}' : {}", document.getName(), e.getMessage());
            return null;
        }
    }


}
