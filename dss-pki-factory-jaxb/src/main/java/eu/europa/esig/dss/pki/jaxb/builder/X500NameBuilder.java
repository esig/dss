package eu.europa.esig.dss.pki.jaxb.builder;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * Builds an X500Name for a certificate to be generated
 *
 */
public class X500NameBuilder {

    /** Name of the certificate owner */
    private String name;

    /** Person's full name */
    private String commonName;

    /** Name of the organization */
    private String organisation;

    /** Name of the organization unit */
    private String organisationUnit;

    /** Two-letter ISO 3166 country code */
    private String country;

    /** Pseudonym */
    private String pseudo;

    /**
     * Sets the name of the certificate owner
     *
     * @param name {@link String}
     * @return {@link X500NameBuilder} this
     */
    public X500NameBuilder name(String name) {
        this.name = name;
        return this;
    }

    /**
     * Sets the person's full name
     *
     * @param commonName {@link String}
     * @return {@link X500NameBuilder} this
     */
    public X500NameBuilder commonName(String commonName) {
        this.commonName = commonName;
        return this;
    }

    /**
     * Sets the organization name
     *
     * @param organisation {@link String}
     * @return {@link X500NameBuilder} this
     */
    public X500NameBuilder organisation(String organisation) {
        this.organisation = organisation;
        return this;
    }

    /**
     * Sets the organization unit name
     *
     * @param organisationUnit {@link String}
     * @return {@link X500NameBuilder} this
     */
    public X500NameBuilder organisationUnit(String organisationUnit) {
        this.organisationUnit = organisationUnit;
        return this;
    }

    /**
     * Sets the two-letter ISO 3166 country code
     *
     * @param country {@link String}
     * @return {@link X500NameBuilder} this
     */
    public X500NameBuilder country(String country) {
        this.country = country;
        return this;
    }

    /**
     * Sets the used pseudonym
     *
     * @param pseudo {@link String}
     * @return {@link X500NameBuilder} this
     */
    public X500NameBuilder pseudo(String pseudo) {
        this.pseudo = pseudo;
        return this;
    }

    /**
     * Builds the {@code X500Name}
     *
     * @return {@link X500Name}
     */
    public X500Name build() {
        org.bouncycastle.asn1.x500.X500NameBuilder builder = new org.bouncycastle.asn1.x500.X500NameBuilder();

        if (name != null) {
            builder.addRDN(BCStyle.NAME, name);
        }

        if (commonName != null) {
            builder.addRDN(BCStyle.CN, commonName);
        }

        if (organisation != null) {
            builder.addRDN(BCStyle.O, organisation);
        }

        if (organisationUnit != null) {
            builder.addRDN(BCStyle.OU, organisationUnit);
        }

        if (country != null) {
            builder.addRDN(BCStyle.C, country);
        }

        if (pseudo != null) {
            builder.addRDN(BCStyle.PSEUDONYM, pseudo);
        }

        return builder.build();
    }

}
