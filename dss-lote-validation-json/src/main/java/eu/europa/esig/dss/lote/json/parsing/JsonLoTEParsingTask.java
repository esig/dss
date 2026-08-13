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

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.lote.json.parsing.function.JsonTrustedEntityConverter;
import eu.europa.esig.dss.lote.parsing.AbstractLoTEParsingResult;
import eu.europa.esig.dss.lote.parsing.LoTEParsingResult;
import eu.europa.esig.dss.lote.parsing.predicate.NonEmptyTENamePredicate;
import eu.europa.esig.dss.lote.parsing.predicate.NonEmptyTESInformationPredicate;
import eu.europa.esig.dss.lote.parsing.predicate.NonEmptyTrustedEntityServicePredicate;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.lote.TrustedEntity;
import eu.europa.esig.dss.model.lote.TrustedEntityService;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class performs reading and information extraction from an obtained JWS compact LoTE
 *
 */
public class JsonLoTEParsingTask extends AbstractJsonLoTEParsingTask {

    /** The List Source to parse */
    private final LoTESource loTESource;

    /**
     * The default constructor
     *
     * @param document {@link DSSDocument} List document to parse
     * @param loTESource {@link LoTESource}
     */
    public JsonLoTEParsingTask(DSSDocument document, LoTESource loTESource) {
        super(document);
        Objects.requireNonNull(loTESource, "The TLSource is null");
        this.loTESource = loTESource;
    }

    @Override
    public LoTEParsingResult get() {
        LoTEParsingResult result = new LoTEParsingResult();

        String unverifiedPayload = getUnverifiedLoTEPayload();
        Map<?, ?> jsonLoTEPayload = getJsonLoTEPayload(unverifiedPayload);

        parseSchemeInformation(result, DSSJsonUtils.getAsMap(jsonLoTEPayload, JsonLoTEHeaderParameterNames.LIST_AND_SCHEME_INFORMATION));
        parseTrustedEntitiesList(result, DSSJsonUtils.getAsList(jsonLoTEPayload, JsonLoTEHeaderParameterNames.TRUSTED_ENTITIES_LIST));
        verifyStructure(result, document);

        return result;
    }

    private void parseSchemeInformation(AbstractLoTEParsingResult result, Map<?, ?> listAndSchemeInformation) {
        commonParseListAndSchemeInformation(result, listAndSchemeInformation);
    }

    private void parseTrustedEntitiesList(LoTEParsingResult result, List<?> trustedEntitiesList) {
        if (Utils.isCollectionNotEmpty(trustedEntitiesList)) {
            List<TrustedEntity> trustedEntities = trustedEntitiesList.stream()
                    .map(DSSJsonUtils::toMap).filter(Utils::isMapNotEmpty)
                    .map(new JsonTrustedEntityConverter().territory(result.getTerritory()))
                    .collect(Collectors.toList());
            List<TrustedEntity> filteredTrustedEntities = filter(trustedEntities);
            result.setTrustedEntities(Collections.unmodifiableList(filteredTrustedEntities));
        } else {
            result.setTrustedEntities(Collections.emptyList());
        }
    }

    private List<TrustedEntity> filter(List<TrustedEntity> trustedEntities) {
        List<TrustedEntity> filteredEntities = trustedEntities;

        // 1. Remove TSPs with invalid structure
        filteredEntities = filteredEntities.stream().filter(new NonEmptyTENamePredicate()).collect(Collectors.toList());

        // 2. Filter the TSP with the predicate
        if (loTESource.getTrustedEntityPredicate() != null) {
            filteredEntities = filteredEntities.stream().filter(loTESource.getTrustedEntityPredicate()).collect(Collectors.toList());
        }

        // 3. Foreach TSP, remove invalid trust services
        for (TrustedEntity trustedEntity : filteredEntities) {
            List<TrustedEntityService> services = trustedEntity.getServices();
            if (Utils.isCollectionNotEmpty(services)) {
                List<TrustedEntityService> filteredServices = services;
                filteredServices = filteredServices.stream()
                        .filter(new NonEmptyTESInformationPredicate()).collect(Collectors.toList());

                // 4. Filter the trust services with the predicate
                if (loTESource.getTrustedServicePredicate() != null) {
                    filteredServices = filteredServices.stream()
                            .filter(loTESource.getTrustedServicePredicate()).collect(Collectors.toList());
                }

                if (!filteredServices.isEmpty()) {
                    trustedEntity.setServices(Collections.unmodifiableList(filteredServices));
                }
            }
        }

        // 5. Remove TSPs with empty trust services
        return filteredEntities.stream().filter(new NonEmptyTrustedEntityServicePredicate()).collect(Collectors.toList());
    }

}
