package eu.europa.esig.dss.xades.dom;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a wrapper of a {@code org.w3c.dom.Document},
 * containing utility methods as well as common cached values
 *
 */
public class XAdESDOMDocument {

    /** XML DOM Document */
    private final Document document;

    /** This variable contains the list of {@code XAdESPaths} adapted to the specific signature schema */
    private final List<XAdESPath> xadesPathsHolders;

    /** Cached list of ds:Signature nodes, except counter signatures */
    private NodeList signatureNodes;

    /** Stores the state of the Id browsing procedure */
    private boolean idBrowsingCompleted;

    /**
     * Default constructor instantiating a XAdES DOM document using XAdES 1.3.2 namespace paths
     *
     * @param document {@link Document}
     */
    public XAdESDOMDocument(final Document document) {
        this(document, Collections.singletonList(new XAdES132Path()));
    }

    /**
     * Constructor with provided XAdES Path holders.
     * The method instantiates a new XAdES Path list based on the provided one.
     *
     * @param document {@link Document}
     * @param xadesPathsHolders a list of {@link XAdESPath}s
     */
    public XAdESDOMDocument(final Document document, final List<XAdESPath> xadesPathsHolders) {
        Objects.requireNonNull(document, "Document cannot be null!");
        Objects.requireNonNull(xadesPathsHolders, "XAdES Path holders cannot be null!");
        this.document = document;
        this.xadesPathsHolders = new ArrayList<>(xadesPathsHolders);
    }

    /**
     * Gets the DOM Document
     *
     * @return {@link Document}
     */
    public Document getDocument() {
        return document;
    }

    /**
     * Gets a list of registered XAdES Path holders
     *
     * @return a list of {@link XAdESPath}s
     */
    public List<XAdESPath> getXAdESPathHolders() {
        return xadesPathsHolders;
    }

    /**
     * Gets a node list containing all ds:Signature elements present within the document,
     * with exception to counter signatures
     *
     * @return {@link NodeList}
     */
    public NodeList getSignatureNodes() {
        if (signatureNodes == null) {
            signatureNodes = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(document);
        }
        return signatureNodes;
    }

    /**
     * Gets element with the requested Id.
     * This method uses a cached map of identifiers for a value extraction
     *
     * @param id {@link String} to get
     * @return {@link Element}
     */
    public Element getElementById(String id) {
        recursiveIdBrowse();
        id = DomUtils.getId(id);
        return document.getElementById(id);
    }

    /**
     * An ID attribute can only be dereferenced if it is declared in the validation context. This behaviour is caused by
     * the fact that the attribute does not have attached type of information. Another solution is to parse the XML
     * against some DTD or XML schema. This process adds the necessary type of information to each ID attribute.
     */
    public void recursiveIdBrowse() {
        if (!idBrowsingCompleted) {
            recursiveIdBrowse(document.getDocumentElement());
            idBrowsingCompleted = true;
        }
    }

    /**
     * Browsers element recursively and enables their Ids
     *
     * @param element {@link Element}
     */
    protected void recursiveIdBrowse(final Element element) {
        setIDIdentifier(element);
        for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {
            final Node childNode = element.getChildNodes().item(ii);
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                recursiveIdBrowse((Element) childNode);
            }
        }
    }

    /**
     * If this method finds an attribute with names ID (case-insensitive) then declares it to be a user-determined ID
     * attribute.
     *
     * @param childElement {@link Element}
     */
    protected void setIDIdentifier(final Element childElement) {
        final NamedNodeMap attributes = childElement.getAttributes();
        for (int jj = 0; jj < attributes.getLength(); jj++) {

            final Node item = attributes.item(jj);
            final String localName = item.getLocalName();
            final String nodeName = item.getNodeName();
            if (localName != null && Utils.areStringsEqualIgnoreCase(XMLDSigAttribute.ID.getAttributeName(), localName)) {
                childElement.setIdAttribute(nodeName, true);
                break;
            }
        }
    }

}
