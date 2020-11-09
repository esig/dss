package eu.europa.esig.dss.asic.common;

import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * The interface provides utilities for data extraction/creation of ZIP-archives
 *
 */
public interface ZipContainerHandler {

	/**
	 * Extracts a list of {@code DSSDocument} from the given ZIP-archive
	 * 
	 * @param zipPackage {@link DSSDocument}
	 * @return a list of {@link DSSDocument}s
	 */
	List<DSSDocument> extractContainerContent(DSSDocument zipPackage);

	/**
	 * Returns a list of ZIP archive entry names
	 * 
	 * @param zipPackage {@link DSSDocument}
	 * @return a list of {@link String} entry names
	 */
	List<String> extractEntryNames(DSSDocument zipPackage);

	/**
	 * Creates a ZIP-Archive with the given {@code containerEntries}
	 * 
	 * @param containerEntries a list of {@link DSSDocument}s to embed into the new container instance
	 * @param zipComment (Optional) {@link String} defined a zipComment
	 * @return {@link DSSDocument} ZIP-Archive
	 */
	DSSDocument createZipArchive(List<DSSDocument> containerEntries, String zipComment);

}
