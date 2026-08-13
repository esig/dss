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
package eu.europa.esig.dss.lote.xml.parsing;

import eu.europa.esig.dss.enumerations.ListType;
import eu.europa.esig.dss.lote.parsing.AbstractLoTEParsingResult;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.job.parsing.ParsingTask;
import eu.europa.esig.dss.xades.lote.XmlLoTEStructureVerifier;
import eu.europa.esig.lote.jaxb.ListOfTrustedEntitiesType;
import eu.europa.esig.lote.jaxb.LoTEListAndSchemeInformationType;
import eu.europa.esig.lote.jaxb.NextUpdateType;
import eu.europa.esig.lote.jaxb.NonEmptyURIListType;
import eu.europa.esig.lote.xml.LOTEFacade;

import javax.xml.datatype.XMLGregorianCalendar;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Objects;

/**
 * Abstract class to parse an XML LoTE
 *
 */
public abstract class AbstractXmlLoTEParsingTask implements ParsingTask {

    /** Document ot parse */
    private final DSSDocument document;

    /**
     * The default constructor
     *
     * @param document {@link DSSDocument} List document to parse
     */
    protected AbstractXmlLoTEParsingTask(DSSDocument document) {
        Objects.requireNonNull(document, "Document is null");
        this.document = document;
    }

    /**
     * Gets the {@code ListOfTrustedEntitiesType}
     *
     * @return {@link ListOfTrustedEntitiesType}
     */
    protected ListOfTrustedEntitiesType getJAXBObject() {
        try (InputStream is = document.openStream()) {
            return createLoTEFacade().unmarshall(is, false); // lax processing, validate XSD after
        } catch (Exception e) {
            String message = "Unable to parse binaries. Reason : '%s'";
            // get complete error message in case if the message string is not defined directly
            if (e.getMessage() == null && e.getCause() != null) {
                throw new DSSException(String.format(message, e.getCause().getMessage()), e);
            }
            throw new DSSException(String.format(message, e.getMessage()), e);
        }
    }

    /**
     * This method loads a {@code LOTEFacade}
     *
     * @return {@link LOTEFacade}
     */
    protected LOTEFacade createLoTEFacade() {
        return LOTEFacade.newFacade();
    }

    /**
     * Extracts the common values
     *
     * @param result {@link AbstractLoTEParsingResult}
     * @param schemeInformation {@link LoTEListAndSchemeInformationType}
     */
    protected void commonParseSchemeInformation(AbstractLoTEParsingResult result, LoTEListAndSchemeInformationType schemeInformation) {
        if (schemeInformation != null) {
            extractTSLType(result, schemeInformation);
            extractSequenceNumber(result, schemeInformation);
            extractTerritory(result, schemeInformation);
            extractVersion(result, schemeInformation);
            extractIssueDate(result, schemeInformation);
            extractNextUpdateDate(result, schemeInformation);
            extractDistributionPoints(result, schemeInformation);
            // TODO : add pivots info extraction, pending the 119 602 standard update
        }
    }

    private void extractTSLType(AbstractLoTEParsingResult result, LoTEListAndSchemeInformationType schemeInformation) {
        String loTEType = schemeInformation.getLoTEType();
        if (Utils.isStringNotEmpty(loTEType)) {
            result.setType(ListType.fromUri(loTEType));
        }
    }

    private void extractSequenceNumber(AbstractLoTEParsingResult result, LoTEListAndSchemeInformationType schemeInformation) {
        BigInteger sequenceNumber = schemeInformation.getLoTESequenceNumber();
        if (sequenceNumber != null) {
            result.setSequenceNumber(sequenceNumber.intValue());
        }
    }

    private void extractTerritory(AbstractLoTEParsingResult result, LoTEListAndSchemeInformationType schemeInformation) {
        result.setTerritory(schemeInformation.getSchemeTerritory());
    }

    private void extractVersion(AbstractLoTEParsingResult result, LoTEListAndSchemeInformationType schemeInformation) {
        BigInteger versionIdentifier = schemeInformation.getLoTEVersionIdentifier();
        if (versionIdentifier != null) {
            result.setVersion(versionIdentifier.intValue());
        }
    }

    private void extractIssueDate(AbstractLoTEParsingResult result, LoTEListAndSchemeInformationType schemeInformation) {
        result.setIssueDate(convertToDate(schemeInformation.getListIssueDateTime()));
    }

    private void extractNextUpdateDate(AbstractLoTEParsingResult result, LoTEListAndSchemeInformationType schemeInformation) {
        NextUpdateType nextUpdate = schemeInformation.getNextUpdate();
        if (nextUpdate != null) {
            result.setNextUpdateDate(convertToDate(nextUpdate.getDateTime()));
        }
    }

    private Date convertToDate(XMLGregorianCalendar gregorianCalendar) {
        if (gregorianCalendar != null) {
            GregorianCalendar toGregorianCalendar = gregorianCalendar.toGregorianCalendar();
            if (toGregorianCalendar != null) {
                return toGregorianCalendar.getTime();
            }
        }
        return null;
    }

    private void extractDistributionPoints(AbstractLoTEParsingResult result, LoTEListAndSchemeInformationType schemeInformation) {
        NonEmptyURIListType distributionPoints = schemeInformation.getDistributionPoints();
        if (distributionPoints != null && Utils.isCollectionNotEmpty(distributionPoints.getURI())) {
            result.setDistributionPoints(Collections.unmodifiableList(distributionPoints.getURI()));
        } else {
            result.setDistributionPoints(Collections.emptyList());
        }
    }

    /**
     * Verifies the structure conformity of the List of Trusted Entities
     *
     * @param result {@link AbstractLoTEParsingResult}
     */
    protected void verifyStructure(AbstractLoTEParsingResult result) {
        List<String> structureValidationMessagesResult = new XmlLoTEStructureVerifier().validate(document);
        if (Utils.isCollectionNotEmpty(structureValidationMessagesResult)) {
            result.setStructureValidationMessages(structureValidationMessagesResult);
        }
    }

}
