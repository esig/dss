package eu.europa.ec.markt.dss.parameter;

import eu.europa.ec.markt.dss.exception.DSSException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.w3c.dom.Element;

/**
 * This class acts as a middle-layer for the Santuario Reference class, which does not provide a public constructor
 */

public class DSSSantuarioReference extends Reference {

	/**
	 * @param element
	 * @param baseURI
	 * @param manifest
	 * @param secureValidation
	 * @throws XMLSecurityException
	 */
	public DSSSantuarioReference (Element element, String baseURI, Manifest manifest, boolean secureValidation) throws XMLSecurityException {

		super(element, baseURI, null, secureValidation);
	}
}
