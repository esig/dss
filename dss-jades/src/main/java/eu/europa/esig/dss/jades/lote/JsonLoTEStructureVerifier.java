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

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.json.JSONSchemaAbstractUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class verifies a structure of a TS 119 602 JSON List of Trusted Entities
 *
 */
public class JsonLoTEStructureVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(JsonLoTEStructureVerifier.class);

    /** Defines whether the current validation of the JSON LoTE is performed for signing */
    private boolean signingMode;

    /**
     * Default constructor.
     */
    public JsonLoTEStructureVerifier() {
        // empty
    }

    /**
     * Sets whether the current operation is the JSON List of Trusted Entities signing.
     * If enabled, verifies that no ds:Signature element is present within the JSON List of Trusted Entities.
     * Otherwise, verifies presence and validity of the ds:Signature element.
     * Default : FALSE (verifies that the signature is not present)
     *
     * @param signingMode whether the validation is performed for the JSON List of Trusted Entities signing
     * @return this {@link JsonLoTEStructureVerifier}
     */
    public JsonLoTEStructureVerifier setSigningMode(boolean signingMode) {
        this.signingMode = signingMode;
        return this;
    }

    /**
     * This method validates the JSON List of Trusted Entities's conformity to the schema
     *
     * @param dssDocument {@link DSSDocument} JSON List of Trusted Entities to be validated
     * @return a list of {@link String}s indicating errors occurred during the conformity evaluation
     */
    public List<String> validate(final DSSDocument dssDocument) {
        Objects.requireNonNull(dssDocument, "Document to be validated cannot be null!");
        assertLoTEUtilsLoaded();

        final List<String> errors = new ArrayList<>();
        InputStream loteIS;
        if (signingMode) {
            if (!DSSJsonUtils.isJsonDocument(dssDocument)) {
                return Collections.singletonList("The document is not a valid JSON document!");
            }
            loteIS = dssDocument.openStream();
            
        } else {
            JWSCompactSerializationParser jwsParser = new JWSCompactSerializationParser(dssDocument);
            if (!jwsParser.isSupported()) {
                return Collections.singletonList("The document is not conformant to the JWS Compact Serialization format!");
            }
            
            JWS jws;
            try {
                jws = jwsParser.parse();
            } catch (Exception e) {
                LOG.warn("Unable to parse JWS : {}", e.getMessage(), e);
                return Collections.singletonList(String.format("Not conformant JWS : %s", e.getMessage()));
            }
            errors.addAll(DSSJsonUtils.validateAgainstJAdESSchema(jws));
            loteIS = new ByteArrayInputStream(jws.getUnverifiedPayloadBytes());
        }

        List<String> schemaValidationErrors = validateAgainstSchema(loteIS, LOTEJsonUtilsProvider.getUtils());
        if (Utils.isCollectionNotEmpty(schemaValidationErrors)) {
            errors.addAll(schemaValidationErrors);
        }
        return errors;
    }

    /**
     * This method validates the JSON List of Trusted Entities's conformity to the schema
     *
     * @param loteDocument {@link String} containing a JSON List of Trusted Entities to be validated
     * @return a list of {@link String}s indicating errors occurred during the conformity evaluation
     */
    public List<String> validate(String loteDocument) {
        Objects.requireNonNull(loteDocument, "Document to be validated cannot be null!");
        return validate(new InMemoryDocument(loteDocument.getBytes()));
    }

    /**
     * Verifies whether the {@code LOTEJsonUtils} is available and 'specs-lote-json' module is successfully loaded
     */
    protected void assertLoTEUtilsLoaded() {
        try {
            Class.forName("eu.europa.esig.lote.json.LOTEJsonUtils");
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            throw new ExceptionInInitializerError(
                    "No implementation found for List of Trusted Entities JSON Schema Utils in classpath, " +
                            "please include 'specs-lote-json' module for structure validation.");
        }
    }

    private List<String> validateAgainstSchema(InputStream inputStream, JSONSchemaAbstractUtils utils) {
        return utils.validateAgainstSchema(inputStream);
    }

}
