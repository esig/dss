package eu.europa.esig.dss.spi.client.http;

import java.io.Serializable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;

public interface DSSFileLoader extends Serializable {
	
	/**
	 * Returns DSSDocument from the provided url
	 * @param url {@link String} url of the document to obtain
	 * @return {@link DSSDocument} retrieved document
	 * @throws DSSException in case of DataLoader error
	 */
	DSSDocument getDocument(final String url) throws DSSException;
	
	/**
	 * Removes the file from FileSystem with the given url
	 * @param url {@link String} url of the remote file location (the same what was used on file saving)
	 * @return TRUE when file was successfully deleted, FALSE otherwise
	 */
	boolean remove(final String url);

}
