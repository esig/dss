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
package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.parsing.ParsingUtils;
import eu.europa.esig.dss.tsl.source.LOTLSource;

import java.util.concurrent.Callable;

/**
 * Processes a pivot analysis
 */
public class PivotProcessing extends AbstractAnalysis implements Callable<PivotProcessingResult> {

	/** The pivot source */
	private final LOTLSource pivotSource;

	/** The cache access of the record */
	private final CacheAccessByKey cacheAccess;

	/**
	 * Default constructor
	 *
	 * @param source {@link LOTLSource} pivot source
	 * @param cacheAccess {@link CacheAccessByKey}
	 * @param dssFileLoader {@link DSSFileLoader}
	 */
	public PivotProcessing(final LOTLSource source, final CacheAccessByKey cacheAccess,
						   final DSSFileLoader dssFileLoader) {
		super(cacheAccess, dssFileLoader);
		this.pivotSource = source;
		this.cacheAccess = cacheAccess;
	}

	@Override
	public PivotProcessingResult call() throws Exception {

		DSSDocument pivot = download(pivotSource.getUrl());

		if (pivot != null) {

			lotlParsing(pivot, pivotSource);

			ParsingCacheDTO parsingResult = cacheAccess.getParsingReadOnlyResult();
			OtherTSLPointer xmllotlPointer = ParsingUtils.getXMLLOTLPointer(parsingResult);
			
			if (xmllotlPointer != null) {
				return new PivotProcessingResult(pivot, getLOTLAnnouncedCertificateSource(xmllotlPointer), xmllotlPointer.getLocation());
			}
		}

		return null;
	}

	private CertificateSource getLOTLAnnouncedCertificateSource(OtherTSLPointer currentLOTLPointer) {
		CertificateSource certificateSource = new CommonCertificateSource();
		for (CertificateToken certificate : currentLOTLPointer.getCertificates()) {
			certificateSource.addCertificate(certificate);
		}
		return certificateSource;
	}

}
