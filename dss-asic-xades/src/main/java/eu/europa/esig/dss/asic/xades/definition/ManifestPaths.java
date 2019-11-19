package eu.europa.esig.dss.asic.xades.definition;

import eu.europa.esig.dss.definition.AbstractPaths;

public class ManifestPaths extends AbstractPaths {

	public static final String FILE_ENTY_PATH = fromCurrentPosition(ManifestElement.MANIFEST, ManifestElement.FILE_ENTRY);

	public static final String FULL_PATH_ATTRIBUTE = ManifestNamespace.NS.getPrefix() + ':' + ManifestAttribute.FULL_PATH.getAttributeName();

	public static final String MEDIA_TYPE_ATTRIBUTE = ManifestNamespace.NS.getPrefix() + ':' + ManifestAttribute.MEDIA_TYPE.getAttributeName();

}
