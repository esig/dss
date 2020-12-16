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
package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.tsl.function.LOTLSigningCertificatesAnnouncementSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * Detects a change of the OJ URL change
 */
public class OJUrlChangeDetection implements AlertDetector<LOTLInfo> {

	/** The LOTL source */
	private final LOTLSource lotlSource;

	/**
	 * Default constructor
	 *
	 * @param lotlSource {@link LOTLSource}
	 */
	public OJUrlChangeDetection(LOTLSource lotlSource) {
		this.lotlSource = lotlSource;
	}

	@Override
	public boolean detect(LOTLInfo info) {
		
		if (!Utils.areStringsEqual(lotlSource.getUrl(), info.getUrl())) {
			return false;
		}

		ParsingInfoRecord parsingCacheInfo = info.getParsingCacheInfo();
		if (parsingCacheInfo.isDesynchronized()) {
			LOTLSigningCertificatesAnnouncementSchemeInformationURI signingCertificatesAnnouncementPredicate = lotlSource
					.getSigningCertificatesAnnouncementPredicate();
			if (signingCertificatesAnnouncementPredicate instanceof OfficialJournalSchemeInformationURI) {
				OfficialJournalSchemeInformationURI journalSchemeInformation = (OfficialJournalSchemeInformationURI) signingCertificatesAnnouncementPredicate;
				String officialJournalURL = journalSchemeInformation.getOfficialJournalURL();
				String signingCertificateAnnouncementUrl = parsingCacheInfo.getSigningCertificateAnnouncementUrl();

				if (!Utils.areStringsEqual(officialJournalURL, signingCertificateAnnouncementUrl)) {
					return true;
				}

			}
		}

		return false;
	}

}
