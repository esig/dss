package eu.europa.esig.dss.xades.lote;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.xpath.XPathUtils;
import eu.europa.esig.lote.xml.definition.LOTENamespace;
import org.w3c.dom.Document;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class contains utils for a XAdES signature creation of an XML List of Trusted Entities
 *
 */
public class XAdESListOfTrustedEntitiesUtils {

    static {
        XPathUtils.registerNamespace(LOTENamespace.NS);
    }

    /**
     * Empty constructor
     */
    private XAdESListOfTrustedEntitiesUtils() {
        // empty
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is 
     * applicable to the given {@code DSSDocument}. Thus, it verifies whether the provided document representing 
     * the XML List of Trusted Entities is conformant to the definition.
     * Returns a list of errors if problems have been found during the validation.
     * Returns an empty list in case of a valid XML List of Trusted Entities conformant to the specified version.
     *
     * @param loteDocument {@link DSSDocument} the XML List of Trusted Entities document to be validated
     * @return a list of {@link String} messages in case of issues on validation, empty list for a passed validation
     */
    public static List<String> validateUnsignedLOTE(DSSDocument loteDocument) throws IllegalInputException {
        Objects.requireNonNull(loteDocument, "XML List of Trusted Entities cannot be null!");

        if (DomUtils.isDOM(loteDocument)) {
            Document documentDom = DomUtils.buildDOM(loteDocument);
            return validateUnsignedLOTE(documentDom);
        } else {
            return Collections.singletonList("The document is not XML!");
        }
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is applicable to the given {@code Document}.
     * Thus, it verifies whether the provided document representing the XML List of Trusted Entities is conformant to the definition
     * and the target version.
     * Returns a list of errors if problems have been found during the validation.
     * Returns an empty list in case of a valid XML List of Trusted Entities conformant to the specified version.
     *
     * @param documentDom {@link Document} the XML List of Trusted Entities document to be validated
     * @return a list of {@link String} messages in case of issues on validation, empty list for a passed validation
     */
    public static List<String> validateUnsignedLOTE(Document documentDom) throws IllegalInputException {
        Objects.requireNonNull(documentDom, "XML List of Trusted Entities cannot be null!");
        final List<String> errorMessages = new ArrayList<>();

        List<String> xsdErrors = new XmlLoTEStructureVerifier()
                .setSigningMode(true)
                .validate(documentDom);
        if (Utils.isCollectionNotEmpty(xsdErrors)) {
            errorMessages.addAll(xsdErrors);
        }
        return errorMessages;
    }

}
