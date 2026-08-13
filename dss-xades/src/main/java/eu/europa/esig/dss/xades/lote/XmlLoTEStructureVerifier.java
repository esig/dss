package eu.europa.esig.dss.xades.lote;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.xpath.XPathUtils;
import eu.europa.esig.lote.xml.definition.LOTENamespace;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.transform.dom.DOMSource;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class verifies a structure of a TS 119 602 XML List of Trusted Entities
 *
 */
public class XmlLoTEStructureVerifier {

    /** Root level of an XML List of Trusted Entities */
    private static final String LOTE_PARENT_ELEMENT = "ListOfTrustedEntities";

    /** Defines whether the current validation of the XML LoTE is performed for signing */
    private boolean signingMode;

    static {
        XPathUtils.registerNamespace(LOTENamespace.NS);
    }

    /**
     * Default constructor.
     */
    public XmlLoTEStructureVerifier() {
        // empty
    }

    /**
     * Sets whether the current operation is the XML List of Trusted Entities signing.
     * If enabled, verifies that no ds:Signature element is present within the XML List of Trusted Entities.
     * Otherwise, verifies presence and validity of the ds:Signature element.
     * Default : FALSE (verifies that the signature is not present)
     *
     * @param signingMode whether the validation is performed for the XML List of Trusted Entities signing
     * @return this {@link XmlLoTEStructureVerifier}
     */
    public XmlLoTEStructureVerifier setSigningMode(boolean signingMode) {
        this.signingMode = signingMode;
        return this;
    }

    /**
     * This method validates the XML List of Trusted Entities's conformity to the schema
     *
     * @param dssDocument {@link DSSDocument} XML List of Trusted Entities to be validated
     * @return a list of {@link String}s indicating errors occurred during the conformity evaluation
     */
    public List<String> validate(final DSSDocument dssDocument) {
        Objects.requireNonNull(dssDocument, "Document to be validated cannot be null!");
        Document document;
        try {
            document = DomUtils.buildDOM(dssDocument);
        } catch (Exception e) {
            return Collections.singletonList("The document is not a valid XML document!");
        }
        return validate(document);
    }

    /**
     * This method validates the XML List of Trusted Entities's conformity to the schema
     *
     * @param document {@link Document} XML List of Trusted Entities to be validated
     * @return a list of {@link String}s indicating errors occurred during the conformity evaluation
     */
    public List<String> validate(final Document document) {
        Objects.requireNonNull(document, "Document to be validated cannot be null!");

        final List<String> errors = new ArrayList<>();
        errors.addAll(validateNamespace(document));
        errors.addAll(validateLoTE(document));
        return errors;
    }

    /**
     * This method validates the XML List of Trusted Entities document against the schema definition
     *
     * @param document {@link Document} containing a List of Trusted Entities to be validated
     * @return a list of {@link String}s
     */
    protected List<String> validateLoTE(Document document) {
        assertLoTEUtilsLoaded();

        final List<String> errors = new ArrayList<>();
        List<String> xsdValidationErrors = validateAgainstXSD(document, XmlLoTEUtilsProvider.getUtils());
        if (Utils.isCollectionNotEmpty(xsdValidationErrors)) {
            errors.addAll(xsdValidationErrors);
        }
        Element signatureElement = getSignatureElement(document);
        errors.addAll(verifySignatureElementPresence(signatureElement));
        return errors;
    }

    /**
     * Verifies whether the {@code LOTEUtils} is available and 'specs-lote-xml' module is successfully loaded
     */
    protected void assertLoTEUtilsLoaded() {
        try {
            Class.forName("eu.europa.esig.lote.xml.LOTEUtils");
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            throw new ExceptionInInitializerError(
                    "No implementation found for List of Trusted Entities XSD Utils in classpath, " +
                            "please include 'specs-lote-xml' module for structure validation.");
        }
    }

    private List<String> validateAgainstXSD(Document document, XSDAbstractUtils xsdUtils) {
        return xsdUtils.validateAgainstXSD(new DOMSource(document));
    }

    private List<String> validateNamespace(Document documentDom) {
        Element documentElement = documentDom.getDocumentElement();
        if (!LOTE_PARENT_ELEMENT.equals(documentElement.getLocalName()) ||
                !LOTENamespace.NS.getUri().equals(documentElement.getNamespaceURI())) {
            return Collections.singletonList(String.format("The root of XML List of Trusted Entities shall be %s:%s element!",
                    LOTENamespace.NS.getPrefix(), LOTE_PARENT_ELEMENT));
        }
        return Collections.emptyList();
    }

    private Element getSignatureElement(Document documentDom) {
        Element documentElement = documentDom.getDocumentElement();
        return getChildElement(documentElement, XMLDSigElement.SIGNATURE);
    }

    private List<String> verifySignatureElementPresence(Element dsSignature) {
        if (signingMode) {
            if (dsSignature != null) {
                return Collections.singletonList("The ds:Signature element shall not be present for XML List of Trusted Entities signing!");
            }
            // no ds:Signature is expected on signing

        } else {
            if (dsSignature == null) {
                return Collections.singletonList("No ds:Signature element is present!");
            }
        }

        return Collections.emptyList();
    }

    private Element getChildElement(Element parentElement, DSSElement targetElement) {
        List<Element> childrenList = getChildElements(parentElement, targetElement);
        if (Utils.collectionSize(childrenList) == 1) {
            return childrenList.get(0);
        }
        return null;
    }

    private List<Element> getChildElements(Element parentElement, DSSElement targetElement) {
        final List<Element> children = new ArrayList<>();
        NodeList childNodes = parentElement.getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node childNode = childNodes.item(i);
            if (Node.ELEMENT_NODE == childNode.getNodeType()) {
                Element childElement = (Element) childNode;
                if (doesMatch(childElement, targetElement)) {
                    children.add(childElement);
                }
            }
        }
        return children;
    }

    private boolean doesMatch(Element element, DSSElement dssElement) {
        return dssElement.isSameTagName(element.getLocalName()) && dssElement.getURI().equals(element.getNamespaceURI());
    }

}
