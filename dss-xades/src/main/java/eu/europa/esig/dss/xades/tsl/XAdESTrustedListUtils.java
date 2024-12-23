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
package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.definition.tsl.TrustedListNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class contains utils for a XAdES signature creation of an XML Trusted List
 *
 */
public final class XAdESTrustedListUtils {

    /** Identifier used for a TL version 5 */
    public static final Integer TL_V5_IDENTIFIER = 5;

    /** Identifier used for a TL version 6 */
    public static final Integer TL_V6_IDENTIFIER = 6;

    /** The path to reach a tl:NextUpdate element */
    public static final String TL_VERSION_IDENTIFIER_PATH = "./tl:SchemeInformation/tl:TSLVersionIdentifier";

    static {
        DomUtils.registerNamespace(TrustedListNamespace.NS);
    }

    /**
     * Empty constructor
     */
    private XAdESTrustedListUtils() {
        // empty
    }

    /**
     * Parses the XML Trusted List and returns the TL version, when present
     *
     * @param documentDom {@link Document} to parse
     * @return {@link Integer} XML Trusted List version
     */
    public static Integer getTSLVersionIdentifier(Document documentDom) {
        Element tlVersionIdentifierElement = DomUtils.getElement(documentDom.getDocumentElement(), TL_VERSION_IDENTIFIER_PATH);
        if (tlVersionIdentifierElement != null) {
            String tlVersionIdentifier = tlVersionIdentifierElement.getTextContent();
            if (tlVersionIdentifier != null && Utils.isStringDigits(tlVersionIdentifier)) {
                return Integer.valueOf(tlVersionIdentifier);
            }
        }
        return null;
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is applicable to the given {@code DSSDocument}.
     * Thus, it verifies whether the provided document representing the XML Trusted List is conformant to the definition
     * and the target version.
     * Returns a list of errors if problems have been found during the validation.
     * Returns an empty list in case of a valid XML Trusted List conformant to the specified version.
     *
     * @param tlDocument {@link DSSDocument} the XML Trusted List document to be validated
     * @param targetTLVersion the target XML Trusted List version (e.g., "5")
     * @return a list of {@link String} messages in case of issues on validation, empty list for a passed validation
     */
    public static List<String> validateUnsignedTrustedList(DSSDocument tlDocument, int targetTLVersion) throws IllegalInputException {
        Objects.requireNonNull(tlDocument, "XML Trusted List cannot be null!");

        if (DomUtils.isDOM(tlDocument)) {
            Document documentDom = DomUtils.buildDOM(tlDocument);
            return validateUnsignedTrustedList(documentDom, targetTLVersion);
        } else {
            return Collections.singletonList("The document is not XML!");
        }
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is applicable to the given {@code Document}.
     * Thus, it verifies whether the provided document representing the XML Trusted List is conformant to the definition
     * and the target version.
     * Returns a list of errors if problems have been found during the validation.
     * Returns an empty list in case of a valid XML Trusted List conformant to the specified version.
     *
     * @param documentDom {@link Document} the XML Trusted List document to be validated
     * @param targetTLVersion the target XML Trusted List version (e.g., "5")
     * @return a list of {@link String} messages in case of issues on validation, empty list for a passed validation
     */
    public static List<String> validateUnsignedTrustedList(Document documentDom, int targetTLVersion) throws IllegalInputException {
        Objects.requireNonNull(documentDom, "XML Trusted List cannot be null!");
        final List<String> errorMessages = new ArrayList<>();

        Integer tlVersionIdentifier = getTSLVersionIdentifier(documentDom);
        if (tlVersionIdentifier == null) {
            errorMessages.add("No TSLVersionIdentifier has been found!");

        } else if (!tlVersionIdentifier.equals(targetTLVersion)) {
            errorMessages.add(String.format("TSL Version '%s' found in the XML Trusted List " +
                    "does not correspond to the target version defined by the builder '%s'! " +
                    "Please modify the document or change to the appropriate builder.", tlVersionIdentifier, targetTLVersion));

        } else {
            List<String> xsdErrors = new TLStructureVerifier()
                    .setSigningMode(true)
                    .setAcceptedTLVersions(Collections.singletonList(targetTLVersion))
                    .validate(documentDom, targetTLVersion);
            if (Utils.isCollectionNotEmpty(xsdErrors)) {
                errorMessages.addAll(xsdErrors);
            }
        }

        return errorMessages;
    }

}
