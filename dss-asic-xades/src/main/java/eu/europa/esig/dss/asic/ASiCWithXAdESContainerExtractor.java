package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.DSSDocument;

public class ASiCWithXAdESContainerExtractor extends AbstractASiCContainerExtractor {

	public ASiCWithXAdESContainerExtractor(DSSDocument archive) {
		super(archive);
	}

	@Override
	boolean isAllowedManifest(String entryName) {
		return entryName.equals(META_INF_FOLDER + "manifest.xml");
	}

	@Override
	boolean isAllowedSignature(String entryName) {
		return ASiCUtils.isXAdES(entryName);
	}

}
