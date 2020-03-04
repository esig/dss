package eu.europa.esig.dss.enumerations;

/**
 * Declares type of the defines identifier
 * Used in XAdES
 * 
 * <pre>
 * 		{@code 
 * 			<xsd:simpleType name="QualifierType">
 * 				<xsd:restriction base="xsd:string">
 * 					<xsd:enumeration value="OIDAsURI"/>
 * 					<xsd:enumeration value="OIDAsURN"/>
 * 				</xsd:restriction>
 * 			</xsd:simpleType>
 * 		}
 * </pre>
 *
 */
public enum ObjectIdentifierQualifier {
	
	/* Identifies object Identifier encoded as URI (e.g. 'http://test/public') */
	OID_AS_URI("OIDAsURI"),

	/* Identifies object Identifier encoded as URN (e.g. 'urn:oid:1.2.840.113549.1.9.16.6.3') */
	OID_AS_URN("OIDAsURN");
	
	private final String value;
	
	private ObjectIdentifierQualifier(String value) {
		this.value = value;
	}

	/**
	 * Returns XML value of the qualifier
	 * 
	 * @return {@link String} value
	 */
	public String getValue() {
		return value;
	}

	/**
	 * Returns an {@code ObjectIdentifierQualifier} instance from the given value
	 * 
	 * @param v {@link String} value to get the {@code ObjectIdentifierQualifier} for
	 * @return {@link ObjectIdentifierQualifier}
	 */
    public static ObjectIdentifierQualifier fromValue(String v) {
        for (ObjectIdentifierQualifier c: ObjectIdentifierQualifier.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
