package eu.europa.esig.dss.tsl.function;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Objects;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;

public class OfficialJournalSchemeInformationURI extends LOTLSigningCertificatesAnnouncementSchemeInformationURI {

	private final String officialJournalURL;

	public OfficialJournalSchemeInformationURI(String officialJournalURL) {
		Objects.requireNonNull(officialJournalURL);
		this.officialJournalURL = officialJournalURL;
	}

	@Override
	public boolean test(NonEmptyMultiLangURIType t) {
		if (t != null && t.getValue() != null) {
			return t.getValue().contains(getOJDomain());
		}
		return false;
	}

	private String getOJDomain() {
		try {
			URL uri = new URL(officialJournalURL);
			return uri.getHost();
		} catch (MalformedURLException e) {
			throw new DSSException("Incorrect format of Official Journal URL [" + officialJournalURL + "] is provided", e);
		}
	}

}
