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

import eu.europa.esig.dss.lote.parsing.LoLoTEParsingResult;
import eu.europa.esig.dss.lote.source.LoLoTESource;
import eu.europa.esig.dss.lote.xml.parsing.function.OtherLoTEPointerConverter;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.lote.jaxb.ListOfTrustedEntitiesType;
import eu.europa.esig.lote.jaxb.LoTEListAndSchemeInformationType;
import eu.europa.esig.lote.jaxb.OtherLoTEPointerType;
import eu.europa.esig.lote.jaxb.OtherLoTEPointersType;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Parses an Xml List of TS 119 602 Lists of Trusted Entities
 *
 */
public class XmlLoLoTEParsingTask extends AbstractXmlLoTEParsingTask {

    /** The List Source to parse */
    private final LoLoTESource loloteSource;

    /**
     * The default constructor
     *
     * @param document {@link DSSDocument} List document to parse
     * @param loloteSource {@link LoLoTESource}
     */
    public XmlLoLoTEParsingTask(DSSDocument document, LoLoTESource loloteSource) {
        super(document);
        Objects.requireNonNull(loloteSource, "The LoLoTESource is null");
        this.loloteSource = loloteSource;
    }

    @Override
    public LoLoTEParsingResult get() {
        LoLoTEParsingResult result = new LoLoTEParsingResult();
        ListOfTrustedEntitiesType jaxbObject = getJAXBObject();

        parseSchemeInformation(result, jaxbObject.getListAndSchemeInformation());
        verifyStructure(result);

        return result;
    }

    private void parseSchemeInformation(LoLoTEParsingResult result, LoTEListAndSchemeInformationType schemeInformation) {
        if (schemeInformation != null) {
            commonParseSchemeInformation(result, schemeInformation);
            extractOtherLoTEPointers(result, schemeInformation);
        }
    }

    private void extractOtherLoTEPointers(LoLoTEParsingResult result, LoTEListAndSchemeInformationType schemeInformation) {
        OtherLoTEPointersType pointersToOtherLoTE = schemeInformation.getPointersToOtherLoTE();
        if (pointersToOtherLoTE != null && Utils.isCollectionNotEmpty(pointersToOtherLoTE.getOtherLoTEPointer())) {
            List<OtherLoTEPointerType> otherLoTEPointers = pointersToOtherLoTE.getOtherLoTEPointer();
            OtherLoTEPointerConverter converter = new OtherLoTEPointerConverter();
            if (loloteSource.getLotePredicate() != null) {
                result.setOtherListPointers(otherLoTEPointers.stream().map(converter).filter(loloteSource.getLotePredicate()).collect(Collectors.toList()));
            }
            if (loloteSource.getLolotePredicate() !=  null) {
                result.setCurrentListPointers(otherLoTEPointers.stream().map(converter).filter(loloteSource.getLolotePredicate()).collect(Collectors.toList()));
            }
        }
    }

}
