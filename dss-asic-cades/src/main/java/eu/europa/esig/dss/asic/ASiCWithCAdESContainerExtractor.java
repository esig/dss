package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.DSSDocument;

public class ASiCWithCAdESContainerExtractor extends AbstractASiCContainerExtractor {

	public ASiCWithCAdESContainerExtractor(DSSDocument archive) {
		super(archive);
	}

	@Override
	boolean isAllowedManifest(String entryName) {
		return entryName.startsWith(META_INF_FOLDER + "ASiCManifest") && entryName.endsWith(".xml");
	}

	@Override
	boolean isAllowedSignature(String entryName) {
		return ASiCUtils.isCAdES(entryName);
	}

}
