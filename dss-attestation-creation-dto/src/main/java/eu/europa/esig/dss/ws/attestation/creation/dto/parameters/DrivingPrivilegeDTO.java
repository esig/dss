/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.ws.attestation.creation.dto.parameters;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * DTO representing a driving privilege as per ISO/IEC 18013-5
 *
 */
public class DrivingPrivilegeDTO implements Serializable {

    private static final long serialVersionUID = 6064844332387506591L;

    /** Vehicle category code as per ISO/IEC 18013-1 Annex B */
    private String vehicleCategoryCode;

    /** Date of issue encoded as full-date */
    private Date issueDate;

    /** Date of expiry encoded as full-date */
    private Date expiryDate;

    /** Array of code info */
    private List<DrivingPrivilegeCodeDTO> codes;

    /**
     * Default constructor
     */
    public DrivingPrivilegeDTO() {
        // empty
    }

    /**
     * Constructor with vehicle category code
     *
     * @param vehicleCategoryCode {@link String}
     */
    public DrivingPrivilegeDTO(String vehicleCategoryCode) {
        this.vehicleCategoryCode = vehicleCategoryCode;
    }

    /**
     * Returns the vehicle category code
     *
     * @return the vehicle category code
     */
    public String getVehicleCategoryCode() {
        return vehicleCategoryCode;
    }

    /**
     * Sets the vehicle category code
     *
     * @param vehicleCategoryCode the vehicle category code to set
     */
    public void setVehicleCategoryCode(String vehicleCategoryCode) {
        this.vehicleCategoryCode = vehicleCategoryCode;
    }

    /**
     * Returns the issue date
     *
     * @return the issue date
     */
    public Date getIssueDate() {
        return issueDate;
    }

    /**
     * Sets the issue date
     *
     * @param issueDate the issue date to set
     */
    public void setIssueDate(Date issueDate) {
        this.issueDate = issueDate;
    }

    /**
     * Returns the expiry date
     *
     * @return the expiry date
     */
    public Date getExpiryDate() {
        return expiryDate;
    }

    /**
     * Sets the expiry date
     *
     * @param expiryDate the expiry date to set
     */
    public void setExpiryDate(Date expiryDate) {
        this.expiryDate = expiryDate;
    }

    /**
     * Returns the codes
     *
     * @return the codes
     */
    public List<DrivingPrivilegeCodeDTO> getCodes() {
        return codes;
    }

    /**
     * Sets the codes
     *
     * @param codes the codes to set
     */
    public void setCodes(List<DrivingPrivilegeCodeDTO> codes) {
        this.codes = codes;
    }

    @Override
    public String toString() {
        return "DrivingPrivilegeDTO [" +
                "vehicleCategoryCode='" + vehicleCategoryCode + '\'' +
                ", issueDate=" + issueDate +
                ", expiryDate=" + expiryDate +
                ", codes=" + codes +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        DrivingPrivilegeDTO that = (DrivingPrivilegeDTO) object;
        return Objects.equals(vehicleCategoryCode, that.vehicleCategoryCode)
                && Objects.equals(issueDate, that.issueDate)
                && Objects.equals(expiryDate, that.expiryDate)
                && Objects.equals(codes, that.codes);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(vehicleCategoryCode);
        result = 31 * result + Objects.hashCode(issueDate);
        result = 31 * result + Objects.hashCode(expiryDate);
        result = 31 * result + Objects.hashCode(codes);
        return result;
    }

}
