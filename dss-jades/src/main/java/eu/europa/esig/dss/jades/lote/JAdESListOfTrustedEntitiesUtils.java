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
package eu.europa.esig.dss.jades.lote;

import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;
import java.util.Objects;

/**
 * This class contains utils for a JAdES signature creation of an JSON List of Trusted Entities
 *
 */
public class JAdESListOfTrustedEntitiesUtils {

    /**
     * Empty constructor
     */
    private JAdESListOfTrustedEntitiesUtils() {
        // empty
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is 
     * applicable to the given {@code DSSDocument}. Thus, it verifies whether the provided document representing 
     * the JSON List of Trusted Entities is conformant to the definition.
     * Returns a list of errors if problems have been found during the validation.
     * Returns an empty list in case of a valid JSON List of Trusted Entities conformant to the specified version.
     *
     * @param loteDocument {@link DSSDocument} the JSON List of Trusted Entities document to be validated
     * @return a list of {@link String} messages in case of issues on validation, empty list for a passed validation
     */
    public static List<String> validateUnsignedLOTE(DSSDocument loteDocument) {
        Objects.requireNonNull(loteDocument, "JSON List of Trusted Entities cannot be null!");
        return new JsonLoTEStructureVerifier().setSigningMode(true).validate(loteDocument);
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is
     * applicable to the given JSON {@code String}. Thus, it verifies whether the provided document representing
     * the JSON List of Trusted Entities is conformant to the definition.
     * Returns a list of errors if problems have been found during the validation.
     * Returns an empty list in case of a valid JSON List of Trusted Entities conformant to the specified version.
     *
     * @param loteDocument {@link String} the JSON List of Trusted Entities document to be validated
     * @return a list of {@link String} messages in case of issues on validation, empty list for a passed validation
     */
    public static List<String> validateUnsignedLOTE(String loteDocument) {
        Objects.requireNonNull(loteDocument, "JSON List of Trusted Entities cannot be null!");
        return new JsonLoTEStructureVerifier().setSigningMode(true).validate(loteDocument);
    }

}
