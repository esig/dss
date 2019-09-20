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

}
