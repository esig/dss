package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.tsl.function.LOTLSigningCertificatesAnnouncementSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;

public class OJUrlChangeDetection implements Detection<LOTLInfo> {

	private final LOTLSource lotlSource;

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
