package eu.europa.esig.dss.pki.jaxb.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

public class X500NameBuilder {

    private String name;
    private String commonName;
    private String organisation;
    private String organisationUnit;
    private String country;
    private String pseudo;

    public X500NameBuilder name(String name) {
        this.name = name;
        return this;
    }

    public X500NameBuilder commonName(String commonName) {
        this.commonName = commonName;
        return this;
    }

    public X500NameBuilder organisation(String organisation) {
        this.organisation = organisation;
        return this;
    }

    public X500NameBuilder organisationUnit(String organisationUnit) {
        this.organisationUnit = organisationUnit;
        return this;
    }

    public X500NameBuilder country(String country) {
        this.country = country;
        return this;
    }

    public X500NameBuilder pseudo(String pseudo) {
        this.pseudo = pseudo;
        return this;
    }

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
