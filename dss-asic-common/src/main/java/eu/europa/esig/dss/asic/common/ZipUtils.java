package eu.europa.esig.dss.asic.common;

import java.util.List;
import java.util.Objects;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * The class is used for processing (reading and creation) of ZIP archives
 * 
 * See zipContainerHandler
 *
 */
public final class ZipUtils {

	private static ZipUtils singleton;

	/**
	 * Provides utils for ZIP-archive content extraction
	 */
	private ZipContainerHandler zipContainerHandler = new SecureContainerHandler();

	private ZipUtils() {
	}

	/**
	 * Returns an instance of the ZipUtils class
	 * 
	 * @return {@link ZipUtils} singleton
	 */
	public static ZipUtils getInstance() {
		if (singleton == null) {
			singleton = new ZipUtils();
		}
		return singleton;
	}

	/**
	 * Sets a handler to process ZIP-content retrieving
	 * 
	 * Default : {@code SecureContainerHandler}
	 * 
	 * @param zipContainerHandler {@link ZipContainerHandler}
	 */
	public void setZipContainerHandler(ZipContainerHandler zipContainerHandler) {
		Objects.requireNonNull(zipContainerHandler, "zipContainerHandler shall be defined!");
		this.zipContainerHandler = zipContainerHandler;
	}

	/**
	 * Extracts a list of {@code DSSDocument} from the given ZIP-archive
	 * 
	 * @param zipPackage {@link DSSDocument}
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> extractContainerContent(DSSDocument zipPackage) {
		return zipContainerHandler.extractContainerContent(zipPackage);
	}

	/**
	 * Returns a list of ZIP archive entry names
	 * 
	 * @param zipPackage {@link DSSDocument}
	 * @return a list of {@link String} entry names
	 */
	public List<String> extractEntryNames(DSSDocument zipPackage) {
		return zipContainerHandler.extractEntryNames(zipPackage);
	}

	/**
	 * Creates a ZIP-Archive with the given {@code containerEntries}
	 * 
	 * @param containerEntries a list of {@link DSSDocument}s to embed into the new
	 *                         container instance
	 * @param zipComment       (Optional) {@link String} defined a zipComment
	 * @return {@link DSSDocument} ZIP-Archive
	 */
	public DSSDocument createZipArchive(List<DSSDocument> containerEntries, String zipComment) {
		return zipContainerHandler.createZipArchive(containerEntries, zipComment);
	}

}
