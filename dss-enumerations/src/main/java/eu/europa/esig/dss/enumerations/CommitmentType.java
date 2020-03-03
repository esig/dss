package eu.europa.esig.dss.enumerations;

import java.util.List;

/**
 * Represents an identifier type with the following properties :
 * - identifier (URI for XAdES and/or OID for CAdES);
 * - description;
 * - document references;
 *
 */
public interface CommitmentType extends OidAndUriBasedEnum, OidDescription {
	
	/**
	 * Returns a list of URI-based references
	 * NOTE: used in XAdES
	 * 
	 * @return a list of URI {@link String} references
	 */
	public List<String> getDocumentationReferences();

}
