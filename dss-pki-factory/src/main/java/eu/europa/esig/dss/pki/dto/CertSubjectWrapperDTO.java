package eu.europa.esig.dss.pki.dto;

import eu.europa.esig.pki.manifest.CertificateType;
import eu.europa.esig.dss.utils.Utils;

public class CertSubjectWrapperDTO {

    private String commonName;
    private String pseudo;
    private String country;
    private String organization;

    protected CertSubjectWrapperDTO() {
        super();
    }

    public CertSubjectWrapperDTO(CertificateType cert, String countryAttribute, String organizationAttribute) {
        this.commonName = cert.getSubject();
        this.pseudo = cert.getPseudo();
        if (!Utils.isStringEmpty(cert.getCountry())) {
            this.country = cert.getCountry();
        } else if (!Utils.isStringEmpty(countryAttribute)) {
            this.country = countryAttribute;
        }

        if (!Utils.isStringEmpty(cert.getOrganization())) {
            this.organization = cert.getOrganization();
        } else if (!Utils.isStringEmpty(organizationAttribute)) {
            this.organization = organizationAttribute;
        }
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getPseudo() {
        return pseudo;
    }

    public void setPseudo(String pseudo) {
        this.pseudo = pseudo;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((commonName == null) ? 0 : commonName.hashCode());
        result = prime * result + ((country == null) ? 0 : country.hashCode());
        result = prime * result + ((organization == null) ? 0 : organization.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        CertSubjectWrapperDTO other = (CertSubjectWrapperDTO) obj;
        if (commonName == null) {
            if (other.commonName != null) return false;
        } else if (!commonName.equals(other.commonName)) return false;
        if (country == null) {
            if (other.country != null) return false;
        } else if (!country.equals(other.country)) return false;
        if (organization == null) {
            if (other.organization != null) return false;
        } else if (!organization.equals(other.organization)) return false;
        return true;
    }

}