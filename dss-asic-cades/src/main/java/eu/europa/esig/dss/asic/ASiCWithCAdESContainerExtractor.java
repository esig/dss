package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.DSSDocument;

public class ASiCWithCAdESContainerExtractor extends AbstractASiCContainerExtractor {

	public ASiCWithCAdESContainerExtractor(DSSDocument archive) {
		super(archive);
	}

	@Override
	boolean isAllowedManifest(String entryName) {
		return ASiCUtils.isASiCManifestWithCAdES(entryName);
	}

	@Override
	boolean isAllowedSignature(String entryName) {
		return ASiCUtils.isCAdES(entryName);
	}

}
