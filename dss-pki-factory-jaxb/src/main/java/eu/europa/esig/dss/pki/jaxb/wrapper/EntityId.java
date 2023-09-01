package eu.europa.esig.dss.pki.jaxb.wrapper;

import eu.europa.esig.dss.pki.jaxb.XmlEntityKey;

public class EntityId {

    private String issuerName;
    private Long serialNumber;

    public EntityId() {
    }

    public EntityId(String issuerName, Long serialNumber) {
        this.issuerName = issuerName;
        this.serialNumber = serialNumber;
    }

    public EntityId(XmlEntityKey entityKey) {
        this(entityKey.getValue(), entityKey.getSerialNumber());
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public Long getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(Long serialNumber) {
        this.serialNumber = serialNumber;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((issuerName == null) ? 0 : issuerName.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        EntityId other = (EntityId) obj;
        if (issuerName == null) {
            if (other.issuerName != null) return false;
        } else if (!issuerName.equals(other.issuerName)) return false;
        if (serialNumber == null) {
            if (other.serialNumber != null) return false;
        } else if (!serialNumber.equals(other.serialNumber)) return false;
        return true;
    }

    @Override
    public String toString() {
        return "EntityId [issuerName=" + issuerName + ", serialNumber=" + serialNumber + "]";
    }

}
