package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;

public final class ASiCUtils {

	private static final String MIME_TYPE = "mimetype";
	private static final String META_INF_FOLDER = "META-INF/";

	private ASiCUtils() {
	}

	public static boolean isMimetype(String entryName) {
		return MIME_TYPE.equalsIgnoreCase(entryName);
	}

	public static boolean isXAdES(final String entryName) {
		final boolean signature = entryName.endsWith(".xml") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("signature")
				&& !entryName.contains("Manifest");
		return signature;
	}

	public static boolean isCAdES(final String entryName) {
		final boolean signature = entryName.endsWith(".p7s") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("signature");
		return signature;
	}

	public static boolean isASiCManifest(String entryName) {
		final boolean manifest = entryName.endsWith(".xml") && entryName.startsWith(META_INF_FOLDER + "ASiCManifest");
		return manifest;
	}

	public static boolean isASiCContainer(DSSDocument dssDocument) {
		int headerLength = 50;
		byte[] preamble = new byte[headerLength];
		DSSUtils.readToArray(dssDocument, headerLength, preamble);
		if ((preamble[0] == 'P') && (preamble[1] == 'K')) {
			return true;
		}
		return false;
	}
}
