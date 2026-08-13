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
package eu.europa.esig.dss.lote.json.parsing;

import eu.europa.esig.dss.enumerations.ListType;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.lote.JsonLoTEStructureVerifier;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.lote.parsing.AbstractLoTEParsingResult;
import eu.europa.esig.dss.lote.parsing.LoTEParsingResult;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.job.parsing.ParsingTask;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Abstract class to parse a JWS LoTE
 *
 */
public abstract class AbstractJsonLoTEParsingTask implements ParsingTask {

    /** Document ot parse */
    protected final DSSDocument document;

    /**
     * The default constructor
     *
     * @param document {@link DSSDocument} List document to parse
     */
    protected AbstractJsonLoTEParsingTask(DSSDocument document) {
        Objects.requireNonNull(document, "Document is null");
        this.document = document;
    }

    /**
     * Gets the LoTE payload
     *
     * @return {@link String}
     */
    protected String getUnverifiedLoTEPayload() {
        JWSCompactSerializationParser parser = new JWSCompactSerializationParser(document);
        JWS jws = parser.parse();
        return jws.getUnverifiedPayload();
    }

    /**
     * Gets the LoTE payload map representing the signed content of the JSON LoTE
     *
     * @param payloadString {@link String}
     * @return {@link Map}
     */
    protected Map<?, ?> getJsonLoTEPayload(String payloadString) {
        try {
            if (Utils.isStringEmpty(payloadString)) {
                throw new NullPointerException("Payload is null. The detached JWS are not accepted for a LoTE signature.");
            }
            Map<String, Object> jsonMap = DSSJsonUtils.parseJsonStringToMap(payloadString);
            Map<?, ?> lote = DSSJsonUtils.getAsMap(jsonMap, JsonLoTEHeaderParameterNames.LOTE);
            Objects.requireNonNull(lote, "Json LoTE shall have the header 'LoTE' as the root!");
            return lote;

        } catch (Exception e) {
            String message = "Unable to parse binaries. Reason : %s";
            // get complete error message in case if the message string is not defined directly
            if (e.getMessage() == null && e.getCause() != null) {
                throw new DSSException(String.format(message, e.getCause().getMessage()), e);
            }
            throw new DSSException(String.format(message, e.getMessage()), e);
        }
    }

    /**
     * Extracts the common values
     *
     * @param result {@link AbstractLoTEParsingResult}
     * @param listAndSchemeInformation map representing a JSON ListAndSchemeInformation object
     */
    protected void commonParseListAndSchemeInformation(AbstractLoTEParsingResult result, Map<?, ?> listAndSchemeInformation) {
        if (listAndSchemeInformation != null) {
            extractTSLType(result, listAndSchemeInformation);
            extractSequenceNumber(result, listAndSchemeInformation);
            extractTerritory(result, listAndSchemeInformation);
            extractVersion(result, listAndSchemeInformation);
            extractIssueDate(result, listAndSchemeInformation);
            extractNextUpdateDate(result, listAndSchemeInformation);
            extractDistributionPoints(result, listAndSchemeInformation);
        }
    }

    private void extractTSLType(AbstractLoTEParsingResult result, Map<?, ?> listAndSchemeInformation) {
        String loTEType = DSSJsonUtils.getAsString(listAndSchemeInformation, JsonLoTEHeaderParameterNames.LOTE_TYPE);
        if (Utils.isStringNotEmpty(loTEType)) {
            result.setType(ListType.fromUri(loTEType));
        }
    }

    private void extractSequenceNumber(AbstractLoTEParsingResult result, Map<?, ?> listAndSchemeInformation) {
        Number sequenceNumber = DSSJsonUtils.getAsNumber(listAndSchemeInformation, JsonLoTEHeaderParameterNames.LOTE_SEQUENCE_NUMBER);
        if (sequenceNumber != null) {
            result.setSequenceNumber(sequenceNumber.intValue());
        }
    }

    private void extractTerritory(AbstractLoTEParsingResult result, Map<?, ?> listAndSchemeInformation) {
        String schemeTerritory = DSSJsonUtils.getAsString(listAndSchemeInformation, JsonLoTEHeaderParameterNames.SCHEME_TERRITORY);
        if (Utils.isStringNotEmpty(schemeTerritory)) {
            result.setTerritory(schemeTerritory);
        }
    }

    private void extractVersion(AbstractLoTEParsingResult result, Map<?, ?> listAndSchemeInformation) {
        Number versionIdentifier = DSSJsonUtils.getAsNumber(listAndSchemeInformation, JsonLoTEHeaderParameterNames.LOTE_VERSION_IDENTIFIER);
        if (versionIdentifier != null) {
            result.setVersion(versionIdentifier.intValue());
        }
    }

    private void extractIssueDate(AbstractLoTEParsingResult result, Map<?, ?> listAndSchemeInformation) {
        String listIssueDateTimeString = DSSJsonUtils.getAsString(listAndSchemeInformation, JsonLoTEHeaderParameterNames.LIST_ISSUE_DATE_TIME);
        if (Utils.isStringNotEmpty(listIssueDateTimeString)) {
            Date listIssueDateTime = DSSUtils.parseRFCDate(listIssueDateTimeString);
            if (listIssueDateTime != null) {
                result.setIssueDate(listIssueDateTime);
            }
        }
    }

    private void extractNextUpdateDate(AbstractLoTEParsingResult result, Map<?, ?> listAndSchemeInformation) {
        String nextUpdateString = DSSJsonUtils.getAsString(listAndSchemeInformation, JsonLoTEHeaderParameterNames.NEXT_UPDATE);
        if (Utils.isStringNotEmpty(nextUpdateString)) {
            Date nextUpdate = DSSUtils.parseRFCDate(nextUpdateString);
            if (nextUpdate != null) {
                result.setNextUpdateDate(nextUpdate);
            }
        }
    }

    private void extractDistributionPoints(AbstractLoTEParsingResult result, Map<?, ?> listAndSchemeInformation) {
        List<?> distributionPointsList = DSSJsonUtils.getAsList(listAndSchemeInformation, JsonLoTEHeaderParameterNames.DISTRIBUTION_POINTS);
        if (Utils.isCollectionNotEmpty(distributionPointsList)) {
            List<String> distributionPoints = DSSJsonUtils.toListOfStrings(distributionPointsList);
            result.setDistributionPoints(Collections.unmodifiableList(distributionPoints));
        } else {
            result.setDistributionPoints(Collections.emptyList());
        }
    }

    /**
     * Verifies the structure conformity of the List of Trusted Entities
     *
     * @param result {@link LoTEParsingResult}
     * @param loteDocument {@link DSSDocument}
     */
    protected void verifyStructure(AbstractLoTEParsingResult result, DSSDocument loteDocument) {
        List<String> errors = new JsonLoTEStructureVerifier().validate(loteDocument);
        if (Utils.isCollectionNotEmpty(errors)) {
            result.setStructureValidationMessages(errors);
        }
    }

}
