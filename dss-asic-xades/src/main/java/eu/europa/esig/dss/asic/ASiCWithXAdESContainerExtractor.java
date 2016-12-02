package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.DSSDocument;

public class ASiCWithXAdESContainerExtractor extends AbstractASiCContainerExtractor {

	public ASiCWithXAdESContainerExtractor(DSSDocument archive) {
		super(archive);
	}

	@Override
	boolean isAllowedManifest(String entryName) {
		return ASiCUtils.isASiCManifestWithXAdES(entryName);
	}

	@Override
	boolean isAllowedSignature(String entryName) {
		return ASiCUtils.isXAdES(entryName);
	}

}
