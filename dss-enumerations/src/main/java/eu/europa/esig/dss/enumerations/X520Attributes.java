/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.enumerations;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Contains attributes of a certificate's distinguished name
 *
 */
public enum X520Attributes implements OidDescription {

	OBJECTCLASS("objectClass", "2.5.4.0"),

	ALIASEDENTRYNAME("aliasedEntryName", "2.5.4.1"),

	ENCRYPTEDALIASEDENTRYNAME("encryptedAliasedEntryName", "2.5.4.1.2"),

	KNOWLEDGEINFORMATION("knowledgeInformation", "2.5.4.2"),

	COMMONNAME("commonName", "2.5.4.3"),

	ENCRYPTEDCOMMONNAME("encryptedCommonName", "2.5.4.3.2"),

	SURNAME("surname", "2.5.4.4"),

	ENCRYPTEDSURNAME("encryptedSurname", "2.5.4.4.2"),

	SERIALNUMBER("serialNumber", "2.5.4.5"),

	ENCRYPTEDSERIALNUMBER("encryptedSerialNumber", "2.5.4.5.2"),

	COUNTRYNAME("countryName", "2.5.4.6"),

	ENCRYPTEDCOUNTRYNAME("encryptedCountryName", "2.5.4.6.2"),

	LOCALITYNAME("localityName", "2.5.4.7"),

	ENCRYPTEDLOCALITYNAME("encryptedLocalityName", "2.5.4.7.2"),

	COLLECTIVELOCALITYNAME("collectiveLocalityName", "2.5.4.7.1"),

	ENCRYPTEDCOLLECTIVELOCALITYNAME("encryptedCollectiveLocalityName", "2.5.4.7.1.2"),

	STATEORPROVINCENAME("stateOrProvinceName", "2.5.4.8"),

	ENCRYPTEDSTATEORPROVINCENAME("encryptedStateOrProvinceName", "2.5.4.8.2"),

	COLLECTIVESTATEORPROVINCENAME("collectiveStateOrProvinceName", "2.5.4.8.1"),

	ENCRYPTEDCOLLECTIVESTATEORPROVINCENAME("encryptedCollectiveStateOrProvinceName", "2.5.4.8.1.2"),

	STREETADDRESS("streetAddress", "2.5.4.9"),

	ENCRYPTEDSTREETADDRESS("encryptedStreetAddress", "2.5.4.9.2"),

	COLLECTIVESTREETADDRESS("collectiveStreetAddress", "2.5.4.9.1"),

	ENCRYPTEDCOLLECTIVESTREETADDRESS("encryptedCollectiveStreetAddress", "2.5.4.9.1.2"),

	ORGANIZATIONNAME("organizationName", "2.5.4.10"),

	ENCRYPTEDORGANIZATIONNAME("encryptedOrganizationName", "2.5.4.10.2"),

	COLLECTIVEORGANIZATIONNAME("collectiveOrganizationName", "2.5.4.10.1"),

	ENCRYPTEDCOLLECTIVEORGANIZATIONNAME("encryptedCollectiveOrganizationName", "2.5.4.10.1.2"),

	ORGANIZATIONALUNITNAME("organizationalUnitName", "2.5.4.11"),

	ENCRYPTEDORGANIZATIONALUNITNAME("encryptedOrganizationalUnitName", "2.5.4.11.2"),

	COLLECTIVEORGANIZATIONALUNITNAME("collectiveOrganizationalUnitName", "2.5.4.11.1"),

	ENCRYPTEDCOLLECTIVEORGANIZATIONALUNITNAM("encryptedCollectiveOrganizationalUnitNam", "2.5.4.11.1.2"),

	TITLE("title", "2.5.4.12"),

	ENCRYPTEDTITLE("encryptedTitle", "2.5.4.12.2"),

	DESCRIPTION("description", "2.5.4.13"),

	ENCRYPTEDDESCRIPTION("encryptedDescription", "2.5.4.13.2"),

	SEARCHGUIDE("searchGuide", "2.5.4.14"),

	ENCRYPTEDSEARCHGUIDE("encryptedSearchGuide", "2.5.4.14.2"),

	BUSINESSCATEGORY("businessCategory", "2.5.4.15"),

	ENCRYPTEDBUSINESSCATEGORY("encryptedBusinessCategory", "2.5.4.15.2"),

	POSTALADDRESS("postalAddress", "2.5.4.16"),

	ENCRYPTEDPOSTALADDRESS("encryptedPostalAddress", "2.5.4.16.2"),

	COLLECTIVEPOSTALADDRESS("collectivePostalAddress", "2.5.4.16.1"),

	ENCRYPTEDCOLLECTIVEPOSTALADDRESS("encryptedCollectivePostalAddress", "2.5.4.16.1.2"),

	POSTALCODE("postalCode", "2.5.4.17"),

	ENCRYPTEDPOSTALCODE("encryptedPostalCode", "2.5.4.17.2"),

	COLLECTIVEPOSTALCODE("collectivePostalCode", "2.5.4.17.1"),

	ENCRYPTEDCOLLECTIVEPOSTALCODE("encryptedCollectivePostalCode", "2.5.4.17.1.2"),

	POSTOFFICEBOX("postOfficeBox", "2.5.4.18"),

	COLLECTIVEPOSTOFFICEBOX("collectivePostOfficeBox", "2.5.4.18.1"),

	ENCRYPTEDPOSTOFFICEBOX("encryptedPostOfficeBox", "2.5.4.18.2"),

	ENCRYPTEDCOLLECTIVEPOSTOFFICEBOX("encryptedCollectivePostOfficeBox", "2.5.4.18.1.2"),

	PHYSICALDELIVERYOFFICENAME("physicalDeliveryOfficeName", "2.5.4.19"),

	COLLECTIVEPHYSICALDELIVERYOFFICENAME("collectivePhysicalDeliveryOfficeName", "2.5.4.19.1"),

	ENCRYPTEDPHYSICALDELIVERYOFFICENAME("encryptedPhysicalDeliveryOfficeName", "2.5.4.19.2"),

	ENCRYPTEDCOLLECTIVEPHYSICALDELIVERYOFFICENAME("encryptedCollectivePhysicalDeliveryOfficeName", "2.5.4.19.1.2"),

	TELEPHONENUMBER("telephoneNumber", "2.5.4.20"),

	ENCRYPTEDTELEPHONENUMBER("encryptedTelephoneNumber", "2.5.4.20.2"),

	COLLECTIVETELEPHONENUMBER("collectiveTelephoneNumber", "2.5.4.20.1"),

	ENCRYPTEDCOLLECTIVETELEPHONENUMBER("encryptedCollectiveTelephoneNumber", "2.5.4.20.1.2"),

	TELEXNUMBER("telexNumber", "2.5.4.21"),

	ENCRYPTEDTELEXNUMBER("encryptedTelexNumber", "2.5.4.21.2"),

	COLLECTIVETELEXNUMBER("collectiveTelexNumber", "2.5.4.21.1"),

	ENCRYPTEDCOLLECTIVETELEXNUMBER("encryptedCollectiveTelexNumber", "2.5.4.21.1.2"),

	TELETEXTERMINALIDENTIFIER("teletexTerminalIdentifier", "2.5.4.22"),

	ENCRYPTEDTELETEXTERMINALIDENTIFIER("encryptedTeletexTerminalIdentifier", "2.5.4.22.2"),

	COLLECTIVETELETEXTERMINALIDENTIFIER("collectiveTeletexTerminalIdentifier", "2.5.4.22.1"),

	ENCRYPTEDCOLLECTIVETELETEXTERMINALIDENTIFIER("encryptedCollectiveTeletexTerminalIdentifier", "2.5.4.22.1.2"),

	FACSIMILETELEPHONENUMBER("facsimileTelephoneNumber", "2.5.4.23"),

	ENCRYPTEDFACSIMILETELEPHONENUMBER("encryptedFacsimileTelephoneNumber", "2.5.4.23.2"),

	COLLECTIVEFACSIMILETELEPHONENUMBER("collectiveFacsimileTelephoneNumber", "2.5.4.23.1"),

	ENCRYPTEDCOLLECTIVEFACSIMILETELEPHONENUMBER("encryptedCollectiveFacsimileTelephoneNumber", "2.5.4.23.1.2"),

	X121ADDRESS("x121Address", "2.5.4.24"),

	ENCRYPTEDX121ADDRESS("encryptedX121Address", "2.5.4.24.2"),

	INTERNATIONALISDNNUMBER("internationalISDNNumber", "2.5.4.25"),

	ENCRYPTEDINTERNATIONALISDNNUMBER("encryptedInternationalISDNNumber", "2.5.4.25.2"),

	COLLECTIVEINTERNATIONALISDNNUMBER("collectiveInternationalISDNNumber", "2.5.4.25.1"),

	ENCRYPTEDCOLLECTIVEINTERNATIONALISDNNUMBER("encryptedCollectiveInternationalISDNNumber", "2.5.4.25.1.2"),

	REGISTEREDADDRESS("registeredAddress", "2.5.4.26"),

	ENCRYPTEDREGISTEREDADDRESS("encryptedRegisteredAddress", "2.5.4.26.2"),

	DESTINATIONINDICATOR("destinationIndicator", "2.5.4.27"),

	ENCRYPTEDDESTINATIONINDICATOR("encryptedDestinationIndicator", "2.5.4.27.2"),

	PREFERREDDELIVERYMETHOD("preferredDeliveryMethod", "2.5.4.28"),

	ENCRYPTEDPREFERREDDELIVERYMETHOD("encryptedPreferredDeliveryMethod", "2.5.4.28.2"),

	PRESENTATIONADDRESS("presentationAddress", "2.5.4.29"),

	ENCRYPTEDPRESENTATIONADDRESS("encryptedPresentationAddress", "2.5.4.29.2"),

	SUPPORTEDAPPLICATIONCONTEXT("supportedApplicationContext", "2.5.4.30"),

	ENCRYPTEDSUPPORTEDAPPLICATIONCONTEXT("encryptedSupportedApplicationContext", "2.5.4.30.2"),

	MEMBER("member", "2.5.4.31"),

	ENCRYPTEDMEMBER("encryptedMember", "2.5.4.31.2"),

	OWNER("owner", "2.5.4.32"),

	ENCRYPTEDOWNER("encryptedOwner", "2.5.4.32.2"),

	ROLEOCCUPANT("roleOccupant", "2.5.4.33"),

	ENCRYPTEDROLEOCCUPANT("encryptedRoleOccupant", "2.5.4.33.2"),

	SEEALSO("seeAlso", "2.5.4.34"),

	ENCRYPTEDSEEALSO("encryptedSeeAlso", "2.5.4.34.2"),

	USERPASSWORD("userPassword", "2.5.4.35"),

	ENCRYPTEDUSERPASSWORD("encryptedUserPassword", "2.5.4.35.2"),

	USERCERTIFICATE("userCertificate", "2.5.4.36"),

	ENCRYPTEDUSERCERTIFICATE("encryptedUserCertificate", "2.5.4.36.2"),

	CACERTIFICATE("cACertificate", "2.5.4.37"),

	ENCRYPTEDCACERTIFICATE("encryptedCACertificate", "2.5.4.37.2"),

	AUTHORITYREVOCATIONLIST("authorityRevocationList", "2.5.4.38"),

	ENCRYPTEDAUTHORITYREVOCATIONLIST("encryptedAuthorityRevocationList", "2.5.4.38.2"),

	CERTIFICATEREVOCATIONLIST("certificateRevocationList", "2.5.4.39"),

	ENCRYPTEDCERTIFICATEREVOCATIONLIST("encryptedCertificateRevocationList", "2.5.4.39.2"),

	CROSSCERTIFICATEPAIR("crossCertificatePair", "2.5.4.40"),

	ENCRYPTEDCROSSCERTIFICATEPAIR("encryptedCrossCertificatePair", "2.5.4.40.2"),

	NAME("name", "2.5.4.41"),

	GIVENNAME("givenName", "2.5.4.42"),

	ENCRYPTEDGIVENNAME("encryptedGivenName", "2.5.4.42.2"),

	INITIALS("initials", "2.5.4.43"),

	ENCRYPTEDINITIALS("encryptedInitials", "2.5.4.43.2"),

	GENERATIONQUALIFIER("generationQualifier", "2.5.4.44"),

	ENCRYPTEDGENERATIONQUALIFIER("encryptedGenerationQualifier", "2.5.4.44.2"),

	UNIQUEIDENTIFIER("uniqueIdentifier", "2.5.4.45"),

	ENCRYPTEDUNIQUEIDENTIFIER("encryptedUniqueIdentifier", "2.5.4.45.2"),

	DNQUALIFIER("dnQualifier", "2.5.4.46"),

	ENCRYPTEDDNQUALIFIER("encryptedDnQualifier", "2.5.4.46.2"),

	ENHANCEDSEARCHGUIDE("enhancedSearchGuide", "2.5.4.47"),

	ENCRYPTEDENHANCEDSEARCHGUIDE("encryptedEnhancedSearchGuide", "2.5.4.47.2"),

	PROTOCOLINFORMATION("protocolInformation", "2.5.4.48"),

	ENCRYPTEDPROTOCOLINFORMATION("encryptedProtocolInformation", "2.5.4.48.2"),

	DISTINGUISHEDNAME("distinguishedName", "2.5.4.49"),

	ENCRYPTEDDISTINGUISHEDNAME("encryptedDistinguishedName", "2.5.4.49.2"),

	UNIQUEMEMBER("uniqueMember", "2.5.4.50"),

	ENCRYPTEDUNIQUEMEMBER("encryptedUniqueMember", "2.5.4.50.2"),

	HOUSEIDENTIFIER("houseIdentifier", "2.5.4.51"),

	ENCRYPTEDHOUSEIDENTIFIER("encryptedHouseIdentifier", "2.5.4.51.2"),

	SUPPORTEDALGORITHMS("supportedAlgorithms", "2.5.4.52"),

	ENCRYPTEDSUPPORTEDALGORITHMS("encryptedSupportedAlgorithms", "2.5.4.52.2"),

	DELTAREVOCATIONLIST("deltaRevocationList", "2.5.4.53"),

	ENCRYPTEDDELTAREVOCATIONLIST("encryptedDeltaRevocationList", "2.5.4.53.2"),

	DMDNAME("dmdName", "2.5.4.54"),

	ENCRYPTEDDMDNAME("encryptedDmdName", "2.5.4.54.2"),

	CLEARANCE("clearance", "2.5.4.55"),

	ENCRYPTEDCLEARANCE("encryptedClearance", "2.5.4.55.2"),

	DEFAULTDIRQOP("defaultDirQop", "2.5.4.56"),

	ENCRYPTEDDEFAULTDIRQOP("encryptedDefaultDirQop", "2.5.4.56.2"),

	ATTRIBUTEINTEGRITYINFO("attributeIntegrityInfo", "2.5.4.57"),

	ENCRYPTEDATTRIBUTEINTEGRITYINFO("encryptedAttributeIntegrityInfo", "2.5.4.57.2"),

	ATTRIBUTECERTIFICATE("attributeCertificate", "2.5.4.58"),

	ENCRYPTEDATTRIBUTECERTIFICATE("encryptedAttributeCertificate", "2.5.4.58.2"),

	ATTRIBUTECERTIFICATEREVOCATIONLIST("attributeCertificateRevocationList", "2.5.4.59"),

	ENCRYPTEDATTRIBUTECERTIFICATEREVOCATIONLIST("encryptedAttributeCertificateRevocationList", "2.5.4.59.2"),

	CONFKEYINFO("confKeyInfo", "2.5.4.60"),

	ENCRYPTEDCONFKEYINFO("encryptedConfKeyInfo", "2.5.4.60.2"),

	AACERTIFICATE("aACertificate", "2.5.4.61"),

	ATTRIBUTEDESCRIPTORCERTIFICATE("attributeDescriptorCertificate", "2.5.4.62"),

	ATTRIBUTEAUTHORITYREVOCATIONLIST("attributeAuthorityRevocationList", "2.5.4.63"),

	FAMILY_INFORMATION("family-information", "2.5.4.64"),

	PSEUDONYM("pseudonym", "2.5.4.65"),

	COMMUNICATIONSSERVICE("communicationsService", "2.5.4.66"),

	COMMUNICATIONSNETWORK("communicationsNetwork", "2.5.4.67"),

	CERTIFICATIONPRACTICESTMT("certificationPracticeStmt", "2.5.4.68"),

	CERTIFICATEPOLICY("certificatePolicy", "2.5.4.69"),

	PKIPATH("pkiPath", "2.5.4.70"),

	PRIVPOLICY("privPolicy", "2.5.4.71"),

	ROLE("role", "2.5.4.72"),

	DELEGATIONPATH("delegationPath", "2.5.4.73"),

	PROTPRIVPOLICY("protPrivPolicy", "2.5.4.74"),

	XMLPRIVILEGEINFO("xMLPrivilegeInfo", "2.5.4.75"),

	XMLPRIVPOLICY("xmlPrivPolicy", "2.5.4.76"),

	UUIDPAIR("uuidpair", "2.5.4.77"),

	TAGOID("tagOid", "2.5.4.78"),

	UIIFORMAT("uiiFormat", "2.5.4.79"),

	UIIINURN("uiiInUrn", "2.5.4.80"),

	CONTENTURL("contentUrl", "2.5.4.81"),

	PERMISSION("permission", "2.5.4.82"),

	URI("uri", "2.5.4.83"),

	PWDATTRIBUTE("pwdAttribute", "2.5.4.84"),

	USERPWD("userPwd", "2.5.4.85"),

	URN("urn", "2.5.4.86"),

	URL("url", "2.5.4.87"),

	UTMCOORDINATES("utmCoordinates", "2.5.4.88"),

	URNC("urnC", "2.5.4.89"),

	UII("uii", "2.5.4.90"),

	EPC("epc", "2.5.4.91"),

	TAGAFI("tagAfi", "2.5.4.92"),

	EPCFORMAT("epcFormat", "2.5.4.93"),

	EPCINURN("epcInUrn", "2.5.4.94"),

	LDAPURL("ldapUrl", "2.5.4.95"),

	TAGLOCATION("tagLocation", "2.5.4.96"),

	ORGANIZATIONIDENTIFIER("organizationIdentifier", "2.5.4.97"),

	COUNTRYCODE3C("countryCode3c", "2.5.4.98"),

	COUNTRYCODE3N("countryCode3n", "2.5.4.99"),

	DNSNAME("dnsName", "2.5.4.100"),

	EEPKCERTIFICATREVOCATIONLIST("eepkCertificatRevocationList", "2.5.4.101"),

	EEATTRCERTIFICATEREVOCATIONLIST("eeAttrCertificateRevocationList", "2.5.4.102"),

	USERPWDDESCRIPTION("userPwdDescription", "2.5.40.0"),

	PWDVOCABULARYDESCRIPTION("pwdVocabularyDescription", "2.5.40.1"),

	PWDALPHABETDESCRIPTION("pwdAlphabetDescription", "2.5.40.2"),

	PWDENCALGDESCRIPTION("pwdEncAlgDescription", "2.5.40.3"),

	UTMCOORDS("utmCoords", "2.5.40.4"),

	UIIFORM("uiiForm", "2.5.40.5"),

	EPCFORM("epcForm", "2.5.40.6"),

	COUNTRYSTRING3C("countryString3c", "2.5.40.7"),

	COUNTRYSTRING3N("countryString3n", "2.5.40.8"),

	DNSSTRING("dnsString", "2.5.40.9"),

	ATTRIBUTETYPEDESCRIPTION("attributeTypeDescription", "1.3.6.1.4.1.1466.115.121.1.3"),

	BITSTRING("bitString", "1.3.6.1.4.1.1466.115.121.1.6"),

	BOOLEAN("boolean", "1.3.6.1.4.1.1466.115.121.1.7"),

	X509CERTIFICATE("x509Certificate", "1.3.6.1.4.1.1466.115.121.1.8"),

	X509CERTIFICATELIST("x509CertificateList", "1.3.6.1.4.1.1466.115.121.1.9"),

	X509CERTIFICATEPAIR("x509CertificatePair", "1.3.6.1.4.1.1466.115.121.1.10"),

	COUNTRYSTRING("countryString", "1.3.6.1.4.1.1466.115.121.1.11"),

	DN("dn", "1.3.6.1.4.1.1466.115.121.1.12"),

	DELIVERYMETHOD("deliveryMethod", "1.3.6.1.4.1.1466.115.121.1.14"),

	DIRECTORYSTRING("directoryString", "1.3.6.1.4.1.1466.115.121.1.15"),

	DITCONTENTRULEDESCRIPTION("dITContentRuleDescription", "1.3.6.1.4.1.1466.115.121.1.16"),

	DITSTRUCTURERULEDESCRIPTION("dITStructureRuleDescription", "1.3.6.1.4.1.1466.115.121.1.17"),

	ENHANCEDGUIDE("enhancedGuide", "1.3.6.1.4.1.1466.115.121.1.21"),

	FACSIMILETELEPHONENR("facsimileTelephoneNr", "1.3.6.1.4.1.1466.115.121.1.22"),

	FAX("fax", "1.3.6.1.4.1.1466.115.121.1.23"),

	GENERALIZEDTIME("generalizedTime", "1.3.6.1.4.1.1466.115.121.1.24"),

	GUIDE("guide", "1.3.6.1.4.1.1466.115.121.1.25"),

	IA5STRING("ia5String", "1.3.6.1.4.1.1466.115.121.1.26"),

	INTEGER("integer", "1.3.6.1.4.1.1466.115.121.1.27"),

	JPEG("jpeg", "1.3.6.1.4.1.1466.115.121.1.28"),

	MATCHINGRULEDESCRIPTION("matchingRuleDescription", "1.3.6.1.4.1.1466.115.121.1.30"),

	MATCHINGRULEUSEDESCRIPTION("matchingRuleUseDescription", "1.3.6.1.4.1.1466.115.121.1.31"),

	NAMEANDOPTIONALUID("nameAndOptionalUID", "1.3.6.1.4.1.1466.115.121.1.34"),

	NAMEFORMDESCRIPTION("nameFormDescription", "1.3.6.1.4.1.1466.115.121.1.35"),

	NUMERICSTRING("numericString", "1.3.6.1.4.1.1466.115.121.1.36"),

	OBJECTCLASSDESCRIPTION("objectClassDescription", "1.3.6.1.4.1.1466.115.121.1.37"),

	OID("oid", "1.3.6.1.4.1.1466.115.121.1.38"),

	OTHERMAILBOX("otherMailbox", "1.3.6.1.4.1.1466.115.121.1.39"),

	OCTETSTRING("octetString", "1.3.6.1.4.1.1466.115.121.1.40"),

	POSTALADDR("postalAddr", "1.3.6.1.4.1.1466.115.121.1.41"),

	PRESENTATIONADDR("presentationAddr", "1.3.6.1.4.1.1466.115.121.1.43"),

	PRINTABLESTRING("printableString", "1.3.6.1.4.1.1466.115.121.1.44"),

	SUBTREESPEC("subtreeSpec", "1.3.6.1.4.1.1466.115.121.1.45"),

	X509SUPPORTEDALGORITHM("x509SupportedAlgorithm", "1.3.6.1.4.1.1466.115.121.1.49"),

	TELEPHONENR("telephoneNr", "1.3.6.1.4.1.1466.115.121.1.50"),

	TELEXNR("telexNr", "1.3.6.1.4.1.1466.115.121.1.52"),

	UTCTIME("utcTime", "1.3.6.1.4.1.1466.115.121.1.53"),

	LDAPSYNTAXDESCRIPTION("ldapSyntaxDescription", "1.3.6.1.4.1.1466.115.121.1.54"),

	SUBSTRINGASSERTION("substringAssertion", "1.3.6.1.4.1.1466.115.121.1.58"),

	EMAIL_ADDRESS("emailAddress", "1.2.840.113549.1.9.1");
	
	/** Map between X520 Attribute uppercase names and their corresponding OIDs */
	private static final Map<String, String> UPPERCASE_DESCRIPTION_OID = registerUpperCaseDescriptionAndOids();

	/** Map between X520 Attribute OIDs and their descriptions */
	private static final Map<String, String> OID_DESCRIPTION = registerOidAndDescriptions();

	/**
	 * Gets map of X520 Attribute uppercase names and their corresponding OIDs
	 *
	 * @return a map of {@link String} X520 Attribute uppercase names and {@link String} OIDs
	 */
	public static Map<String, String> getUppercaseDescriptionForOids() {
		return Collections.unmodifiableMap(UPPERCASE_DESCRIPTION_OID);
	}

	/**
	 * Gets map of X520 Attribute OIDs and their descriptions
	 *
	 * @return a map of {@link String} X520 Attribute OIDs and {@link String} descriptions
	 */
	public static Map<String, String> getOidDescriptions() {
		return Collections.unmodifiableMap(OID_DESCRIPTION);
	}

	private static Map<String, String> registerOidAndDescriptions() {
		Map<String, String> map = new HashMap<>();
		for (X520Attributes attribute : X520Attributes.values()) {
			map.put(attribute.getOid(), attribute.getDescription());
		}
		return map;
	}

	private static Map<String, String> registerUpperCaseDescriptionAndOids() {
		Map<String, String> map = new HashMap<>();
		for (X520Attributes attribute : X520Attributes.values()) {
			map.put(attribute.name(), attribute.getOid());
		}
		return map;
	}

	/** Description of the attribute */
	private final String description;

	/** OID of the attribute */
	private final String oid;

	/**
	 * Default constructor
	 *
	 * @param description {@link String}
	 * @param oid {@link String}
	 */
	X520Attributes(String description, String oid) {
		this.description = description;
		this.oid = oid;
	}

	@Override
	public String getOid() {
		return oid;
	}

	@Override
	public String getDescription() {
		return description;
	}

}
