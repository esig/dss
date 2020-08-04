package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.ObjectIdentifier;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;

public class SpDocSpecification implements ObjectIdentifier {

	/* Specified in EN 319 132 */
	private final ObjectIdentifierQualifier objectIdentifierQualifier = ObjectIdentifierQualifier.OID_AS_URN;

	/* Oid eg : 2.2.25.1 */
	private final String oid;
	/* Optional description */
	private final String description;
	/* Optional document references */
	private final String[] documentationReferences;

	/**
	 * Constructor for SpDocSpecification
	 * 
	 * @param oid                     the object identifier (eg : 2.2.25.1)
	 * @param description             the optional description
	 * @param documentationReferences the optional documentation references (URIs)
	 */
	public SpDocSpecification(String oid, String description, String[] documentationReferences) {
		this.oid = oid;
		this.description = description;
		this.documentationReferences = documentationReferences;
	}

	@Override
	public String getOid() {
		return oid;
	}

	@Override
	public String getUri() {
		// not used
		return null;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public String[] getDocumentationReferences() {
		return documentationReferences;
	}

	@Override
	public ObjectIdentifierQualifier getQualifier() {
		return objectIdentifierQualifier;
	}

}
