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
package eu.europa.esig.dss.diagnostic.claim;

import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.jaxb.parsers.DateParser;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class represents a user-friendly wrapper of a generic {@code XmlClaim} object,
 * containing an information about a single claim extracted from an attestation Payload.
 * <p>
 * The wrapper may return only one of the following values:
 * - Text; or
 * - Number; or
 * - Boolean; or
 * - DateTime; or
 * - Serialized bytes.
 * <p>
 * Should you need to retrieve any value, you may use the method {@code #getDisplayValue} in order to obtain
 * a String derived from the original value, irrespective of the original claim data type.
 *
 */
public class ClaimWrapper {

    /** Wrapped disclosable claim */
    private final XmlClaim wrapped;

    /** Parent claim */
    private final ClaimWrapper parent;

    /**
     * Default constructor
     *
     * @param wrapped {@link XmlClaim}
     */
    public ClaimWrapper(final XmlClaim wrapped) {
        this(wrapped, null);
    }

    /**
     * Constructor with a parent claim provided
     *
     * @param wrapped {@link XmlClaim}
     * @param parent {@link XmlClaim}
     */
    public ClaimWrapper(final XmlClaim wrapped, final ClaimWrapper parent) {
        Objects.requireNonNull(wrapped, "XmlClaim cannot be null!");
        this.wrapped = wrapped;
        this.parent = parent;
    }

    /**
     * Gets the claim name
     *
     * @return {@link String}
     */
    public String getName() {
        return wrapped.getName();
    }

    /**
     * Gets the claim's namespace (used for mdoc)
     *
     * @return {@link String}
     */
    public String getNamespace() {
        return wrapped.getNamespace();
    }

    /**
     * Gets whether the claim was made selectively disclosable and its value has been obtained from a provided disclosure
     *
     * @return whether the claim's value has been obtained from a disclosure
     */
    public boolean isSelectivelyDisclosable() {
        return wrapped.isDisclosure() != null && wrapped.isDisclosure();
    }

    /**
     * Gets the value as a string.
     * If the value is null or not of a string type, returns null
     *
     * @return {@link String}
     */
    public String getText() {
        return wrapped.getText();
    }

    /**
     * Gets whether the claim value is of String type
     *
     * @return TRUE if the value is of String type, FALSE otherwise
     */
    public boolean isText() {
        return wrapped.getText() != null;
    }

    /**
     * Gets the value as a number.
     * If the value is null or not of a number type, returns null
     *
     * @return {@link BigInteger}
     */
    public BigInteger getNumber() {
        return wrapped.getNumber();
    }

    /**
     * Gets whether the claim value is of Number type
     *
     * @return TRUE if the value is of Number type, FALSE otherwise
     */
    public boolean isNumber() {
        return wrapped.getNumber() != null;
    }

    /**
     * Gets the value as boolean.
     * If the value is null or not of a boolean type, returns null
     *
     * @return {@link Boolean}
     */
    public Boolean getBoolean() {
        return wrapped.isBoolean();
    }

    /**
     * Gets whether the claim value is of Boolean type
     *
     * @return TRUE if the value is of Boolean type, FALSE otherwise
     */
    public boolean isBoolean() {
        return wrapped.isBoolean() != null;
    }

    /**
     * Gets the binary value.
     * If the value is null or not of a binary type, returns null
     *
     * @return byte array
     */
    public byte[] getBinary() {
        return wrapped.getBinary();
    }

    /**
     * Gets whether the claim value is of Binary type
     *
     * @return TRUE if the value is of Binary type, FALSE otherwise
     */
    public boolean isBinary() {
        return wrapped.getBinary() != null;
    }

    /**
     * Gets the value as date.
     * If the value is null or not of a date type, returns null
     *
     * @return {@link Date}
     */
    public Date getDateTime() {
        return wrapped.getDateTime();
    }

    /**
     * Gets whether the claim value is of Date type
     *
     * @return TRUE if the value is of Date type, FALSE otherwise
     */
    public boolean isDateTime() {
        return wrapped.getDateTime() != null;
    }

    /**
     * Gets the value as list.
     * If the value is null or not of a list type, returns null
     *
     * @return {@link List}
     */
    public List<ClaimWrapper> getList() {
        if (!isList()) {
            return null;
        }
        return wrapped.getItem().stream().map(c -> new ClaimWrapper(c, this)).collect(Collectors.toList());
    }

    /**
     * Gets whether the claim value is of a list type.
     *
     * @return TRUE if the value is of list type, FALSE otherwise
     */
    public boolean isList() {
        return wrapped.getItem() != null && !wrapped.getItem().isEmpty();
    }

    /**
     * Gets the value as map.
     * If the value is null or not of a list type, returns null
     *
     * @return {@link List}
     */
    public Map<String, ClaimWrapper> getMap() {
        if (!isMap()) {
            return null;
        }
        return wrapped.getEntry().stream().collect(Collectors.toMap(XmlClaim::getName, c ->  new ClaimWrapper(c, this)));
    }

    /**
     * Gets whether the claim value is of a map type.
     *
     * @return TRUE if the value is of map type, FALSE otherwise
     */
    public boolean isMap() {
        return wrapped.getEntry() != null && !wrapped.getEntry().isEmpty();
    }

    /**
     * Gets whether the claim value is of a null type.
     *
     * @return TRUE if the value is of null type, FALSE otherwise
     */
    public boolean isNull() {
        return getText() == null
                && getNumber() == null
                && getBoolean() == null
                && getBinary() == null
                && getDateTime() == null
                && getList() == null
                && getMap() == null;
    }

    /**
     * Gets the wrapped JAXB disclosable claim object
     *
     * @return {@link XmlClaim}
     */
    public XmlClaim getWrapped() {
        return wrapped;
    }

    /**
     * Gets parent claim, when present
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getParent() {
        return parent;
    }

    /**
     * Checks whether the claim is null or empty
     *
     * @return TRUE if the claim is empty, FALSE otherwise
     */
    public boolean isEmpty() {
        return !isText()
                && !isNumber()
                && !isBoolean()
                && !isBinary()
                && !isDateTime()
                && !isList()
                && !isMap();
    }

    /**
     * Converts the claim's value to its corresponding string representation
     *
     * @return {@link String}
     */
    public String getDisplayValue() {
        if (isText()) {
            return getText();
        } else if (isNumber()) {
            return getNumber().toString();
        } else if (isBoolean()) {
            return getBoolean().toString();
        } else if (isBinary()) {
            return Base64.getEncoder().encodeToString(getBinary());
        } else if (isDateTime()) {
            return new DateParser().toString(getDateTime());
        } else if (isList()) {
            return toDisplayValue(getList());
        } else if (isMap()) {
            return toDisplayValue(getMap());
        } else if (isNull()) {
            return "null";
        }
        return "";
    }

    private String toDisplayValue(List<ClaimWrapper> items) {
        final StringBuilder sb = new StringBuilder();
        Iterator<ClaimWrapper> it = items.iterator();
        while (it.hasNext()) {
            ClaimWrapper claimValue = it.next();
            sb.append(claimValue.getDisplayValue());
            if (it.hasNext()) {
                sb.append(", ");
            }
        }
        return sb.toString();
    }

    private String toDisplayValue(Map<String, ClaimWrapper> entryMap) {
        final StringBuilder sb = new StringBuilder();
        sb.append("{");
        Iterator<Map.Entry<String, ClaimWrapper>> it = entryMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, ClaimWrapper> entry = it.next();
            sb.append("\"");
            sb.append(entry.getKey());
            sb.append("\": ");
            embedValueWithEnvelope(sb, entry.getValue());;
            if (it.hasNext()) {
                sb.append(", ");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    private void embedValueWithEnvelope(StringBuilder sb, ClaimWrapper claim) {
        if (claim.isText() || claim.isDateTime()) {
            sb.append("\"");
        } else if (claim.isList()) {
            sb.append("[");
        }
        sb.append(claim.getDisplayValue());

        if (claim.isText() || claim.isDateTime()) {
            sb.append("\"");
        } else if (claim.isList()) {
            sb.append("]");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ClaimWrapper)) {
            return false;
        }

        ClaimWrapper other = (ClaimWrapper) o;

        // Compare basic attributes
        if (!Objects.equals(getName(), other.getName())) {
            return false;
        }

        if (isSelectivelyDisclosable() != other.isSelectivelyDisclosable()) {
            return false;
        }

        // Compare value types and contents
        if (isText() && other.isText()) {
            return Objects.equals(getText(), other.getText());
        }

        if (isNumber() && other.isNumber()) {
            return Objects.equals(getNumber(), other.getNumber());
        }

        if (isBoolean() && other.isBoolean()) {
            return Objects.equals(getBoolean(), other.getBoolean());
        }

        if (isBinary() && other.isBinary()) {
            return Arrays.equals(getBinary(), other.getBinary());
        }

        if (isDateTime() && other.isDateTime()) {
            return Objects.equals(getDateTime(), other.getDateTime());
        }

        if (isList() && other.isList()) {
            return Objects.equals(getList(), other.getList());
        }

        if (isMap() && other.isMap()) {
            return Objects.equals(getMap(), other.getMap());
        }

        // If types differ or both have no value
        return isEmpty() == other.isEmpty();
    }

    @Override
    public int hashCode() {
        Object value = null;

        if (isText()) {
            value = getText();
        } else if (isNumber()) {
            value = getNumber();
        } else if (isBoolean()) {
            value = getBoolean();
        } else if (isBinary()) {
            value = Arrays.hashCode(getBinary());
        } else if (isDateTime()) {
            value = getDateTime();
        } else if (isList()) {
            value = getList();
        } else if (isMap()) {
            value = getMap();
        }

        return Objects.hash(
                getName(),
                isSelectivelyDisclosable(),
                value
        );
    }

}
