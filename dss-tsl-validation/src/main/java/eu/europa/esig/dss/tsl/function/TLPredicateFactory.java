/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;

import java.util.Arrays;
import java.util.function.Predicate;

/**
 * This class provides utils for creation of common {@code Predicate}s used
 * for {@code TLSource}/{@code LOTLSource} configuration.
 *
 */
public class TLPredicateFactory {

    /**
     * Default constructor
     */
    private TLPredicateFactory() {
    }

    /**
     * This method creates a Predicate used to filter the XML European list of trusted list (LOTL)
     *
     * @return {@link Predicate}
     */
    public static Predicate<OtherTSLPointerType> createEULOTLPredicate() {
        return new EULOTLOtherTSLPointer().and(new XMLOtherTSLPointer());
    }

    /**
     * This method creates a Predicate used to filter the XML European Trusted List (TL)
     *
     * @return {@link Predicate}
     */
    public static Predicate<OtherTSLPointerType> createEUTLPredicate() {
        return new EUTLOtherTSLPointer().and(new XMLOtherTSLPointer());
    }

    /**
     * This method creates a Predicate used to filter an XML Trusted List (TL) defined with a custom TSLType
     *
     * @param tslType {@link String} representing URI present within TSPType element used to define the Trusted List
     * @return {@link Predicate}
     */
    public static Predicate<OtherTSLPointerType> createPredicateWithCustomTSLType(String tslType) {
        return new TypeOtherTSLPointer(tslType).and(new XMLOtherTSLPointer());
    }

    /**
     * This method creates a Predicate used to filter XML European Trusted Lists (TL)
     * with the defined Scheme Territory codes
     *
     * Example : "DE", "FR"
     *
     * @param countryCodes an array of {@link String}s representing Scheme Territory codes to filter Trusted Lists by
     * @return {@link Predicate}
     */
    public static Predicate<OtherTSLPointerType> createEUTLCountryCodePredicate(String... countryCodes) {
        return new SchemeTerritoryOtherTSLPointer(Arrays.asList(countryCodes)).and(new EUTLOtherTSLPointer())
                .and(new XMLOtherTSLPointer());
    }

    /**
     * This method creates a predicate used to filter all XML Trusted Lists (TL)
     *
     * @return {@link Predicate}
     */
    public static Predicate<OtherTSLPointerType> createXMLOtherTSLPointerPredicate() {
        return new XMLOtherTSLPointer();
    }

    /**
     * This method creates a predicate used to filter all PDF Trusted Lists (TL)
     *
     * @return {@link Predicate}
     */
    public static Predicate<OtherTSLPointerType> createPDFOtherTSLPointerPredicate() {
        return new PDFOtherTSLPointer();
    }

    /**
     * This method creates a predicate used to filter all Trusted Lists (TL) with the defined mimetype
     *
     * Example : "application/vnd.etsi.tsl+xml" to filter XML Trusted Lists (TL)
     *
     * @param mimetype {@link String} defyining the MimeType
     * @return {@link Predicate}
     */
    public static Predicate<OtherTSLPointerType> createPredicateWithCustomMimeType(String mimetype) {
        return new MimetypeOtherTSLPointer(mimetype);
    }

}
