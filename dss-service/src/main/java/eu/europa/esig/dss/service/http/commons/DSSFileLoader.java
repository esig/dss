package eu.europa.esig.dss.service.http.commons;

import java.io.Serializable;

import eu.europa.esig.dss.model.DSSDocument;

public interface DSSFileLoader extends Serializable {
	
	/**
	 * Returns DSSDocument from the provided url
	 * @param url {@link String} url of the docuemnt to obtain
	 * @return {@link DSSDocument} retrieved document
	 */
	public DSSDocument getDocument(final String url);
	
	/**
	 * Removes the file from FileSystem with the given url
	 * @param url {@link String} url of the remote file location (the same what was used on file saving)
	 * @return TRUE when file was successfully deleted, FALSE otherwise
	 */
	public boolean remove(final String url);

}
