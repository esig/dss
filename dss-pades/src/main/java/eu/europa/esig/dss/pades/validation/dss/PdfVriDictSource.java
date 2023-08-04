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
package eu.europa.esig.dss.pades.validation.dss;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVriDict;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;

/**
 * This class extracts special information from a VRI dictionary
 *
 */
public class PdfVriDictSource {

    private static final Logger LOG = LoggerFactory.getLogger(PdfVriDictSource.class);

    /** The DSS dictionary */
    private final PdfVriDict pdfVriDict;

    /**
     * Default constructor
     *
     * @param dssDictionary {@link PdfDssDict} DSS dictionary
     * @param vriDictionaryName {@link String} SHA-1 of the signature name
     */
    public PdfVriDictSource(final PdfDssDict dssDictionary, final String vriDictionaryName) {
        List<PdfVriDict> vris = PAdESUtils.getVRIsWithName(dssDictionary, vriDictionaryName);
        if (Utils.collectionSize(vris) == 1) {
            this.pdfVriDict = vris.get(0);
        } else {
            this.pdfVriDict = null;
        }
    }

    /**
     * Returns VRI creation time extracted from 'TU' field
     *
     * @return {@link Date}
     */
    public Date getVRICreationTime() {
        if (pdfVriDict != null) {
            return pdfVriDict.getTUTime();
        }
        return null;
    }

    /**
     * Returns a timestamp token extracted from the VRI dictionary from 'TS' field
     *
     * @return {@link TimestampToken}
     */
    public TimestampToken getTimestampToken() {
        if (pdfVriDict != null) {
            try {
                byte[] tsStream = pdfVriDict.getTSStream();
                if (Utils.isArrayNotEmpty(tsStream)) {
                    return new TimestampToken(pdfVriDict.getTSStream(), TimestampType.VRI_TIMESTAMP);
                }

            } catch (Exception e) {
                LOG.warn("An error occurred while extracting 'TS' timestamp from the corresponding /VRI dictionary : {}", e.getMessage());
            }
        }
        return null;
    }

}
