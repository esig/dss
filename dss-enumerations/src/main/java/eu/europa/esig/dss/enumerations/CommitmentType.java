package eu.europa.esig.dss.enumerations;

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
	 * @return an array of URI {@link String} references
	 */
	public String[] getDocumentationReferences();

}
