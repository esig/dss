package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;

import java.io.Serializable;

/**
 * Represents a "SpDocSpecification" element of a "SignaturePolicyStore"
 *
 */
public class SpDocSpecification implements Serializable {

	/** The OID, e.g. OID : 2.2.25.1 */
	private String id;
	
	/** Optional description */
	private String description;
	
	/** Optional document references */
	private String[] documentationReferences;

	/** Specified in EN 319 132 */
	private ObjectIdentifierQualifier qualifier;

	/**
	 * Get identifier
	 * 
	 * @return {@link String} id
	 */
	public String getId() {
		return id;
	}
	
	/**
	 * Set Identifier (URI or OID)
	 * 
	 * @param id 
	 *           {@link String} (eg : 2.2.25.1 for OID)
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * Get description
	 * 
	 * @return {@link String} description
	 */
	public String getDescription() {
		return description;
	}
	
	/**
	 * Set description
	 * 
	 * @param description {@link String}
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Get documentation references
	 * 
	 * @return an array of {@link String} documentation references
	 */
	public String[] getDocumentationReferences() {
		return documentationReferences;
	}
	
	/**
	 * Set documentation references
	 * 
	 * @param documentationReferences an array of {@link String}s
	 */
	public void setDocumentationReferences(String[] documentationReferences) {
		this.documentationReferences = documentationReferences;
	}

	/**
	 * Get a qualifier (used in XAdES)
	 * 
	 * @return {@link ObjectIdentifierQualifier}
	 */
	public ObjectIdentifierQualifier getQualifier() {
		return qualifier;
	}
	
	/**
	 * Set a qualifier (used in XAdES)
	 * 
	 * @param qualifier {@link ObjectIdentifierQualifier}
	 */
	public void setQualifier(ObjectIdentifierQualifier qualifier) {
		this.qualifier = qualifier;
	}

}
