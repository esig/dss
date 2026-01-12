package eu.europa.esig.dss.xades.dom;

import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import org.w3c.dom.Document;
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

}
