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
package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.model.tsl.OtherTSLPointer;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Contains utils for LOTL/TL parsing
 *
 */
public class ParsingUtils {

	private static final Logger LOG = LoggerFactory.getLogger(ParsingUtils.class);

	/**
	 * Empty constructor
	 */
	private ParsingUtils() {
	}
	
	/**
	 * Extracts XML LOTL Pointer from a parsing cache of a pivot
	 * @param parsingCacheDTO {@link ParsingCacheDTO} to extract value from
	 * @return {@link OtherTSLPointer} XML LOTL Pointer
	 */
	public static OtherTSLPointer getXMLLOTLPointer(final ParsingCacheDTO parsingCacheDTO) {
		int nbLOTLPointersInPivot = 0;
		if (parsingCacheDTO != null && parsingCacheDTO.isResultExist()) {
			List<OtherTSLPointer> lotlOtherPointers = parsingCacheDTO.getLotlOtherPointers();
			nbLOTLPointersInPivot = Utils.collectionSize(lotlOtherPointers);
			if (nbLOTLPointersInPivot == 1) {
				return lotlOtherPointers.get(0);
			}
		} else {
			LOG.warn("The provided parsing cache DTO is null or does not exist!");
		}
		LOG.warn("Unable to find the XML LOTL Pointer in the pivot (nb occurrences : {}). Must be one occurence!", nbLOTLPointersInPivot);
		return null;
	}

	/**
	 * This class extracts a SDIs present in a OtherTSLPointer to a {@code CertificateSource}
	 *
	 * @param currentLOTLPointer {@link OtherTSLPointer} to extract SDIs from
	 * @return {@link CertificateSource}
	 */
	public static CertificateSource getLOTLAnnouncedCertificateSource(OtherTSLPointer currentLOTLPointer) {
		CertificateSource certificateSource = new CommonCertificateSource();
		for (CertificateToken certificate : currentLOTLPointer.getSdiCertificates()) {
			certificateSource.addCertificate(certificate);
		}
		return certificateSource;
	}

}
