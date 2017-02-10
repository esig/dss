package eu.europa.esig.dss.asic;

/**
 * This class contains constants for Manifest and its namespace.
 * 
 * @see <a href="http://docs.oasis-open.org/office/v1.2/OpenDocument-v1.2-part3.pdf">Open Document Format for Office
 *      Applications (OpenDocument) Version 1.2;
 *      Part 3: Packages</a>
 */
public final class ManifestNamespace {

	public static final String NS = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
	public static final String MANIFEST = "manifest:manifest";
	public static final String VERSION = "manifest:version";
	public static final String FILE_ENTRY = "manifest:file-entry";
	public static final String FULL_PATH = "manifest:full-path";
	public static final String MEDIA_TYPE = "manifest:media-type";

	private ManifestNamespace() {
	}
}
