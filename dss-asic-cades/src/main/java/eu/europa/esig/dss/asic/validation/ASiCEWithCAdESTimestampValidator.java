package eu.europa.esig.dss.asic.validation;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.cades.validation.CMSTimestampValidator;
import eu.europa.esig.dss.x509.TimestampType;

public class ASiCEWithCAdESTimestampValidator extends CMSTimestampValidator {

	/* Extracted filenames from ASiCArchiveManifest */
	private final List<String> coveredFilenames;

	public ASiCEWithCAdESTimestampValidator(DSSDocument timestamp, TimestampType type, List<String> coveredFilenames) {
		super(timestamp, type);
		this.coveredFilenames = coveredFilenames;
	}

	public List<String> getCoveredFilenames() {
		return coveredFilenames;
	}

}
