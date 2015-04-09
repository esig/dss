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
package eu.europa.esig.dss.applet.component.model;

public class XsdNode {
    private final String name;
    private final XsdNodeType type;
    private final XsdNodeCardinality cardinality;

    public XsdNode(String name, XsdNodeType type, XsdNodeCardinality cardinality) {
        this.name = name;
        this.type = type;
        this.cardinality = cardinality;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof XsdNode)) return false;

        XsdNode xsdNode = (XsdNode) o;

        if (cardinality != xsdNode.cardinality) return false;
        if (name != null ? !name.equals(xsdNode.name) : xsdNode.name != null) return false;
        if (type != xsdNode.type) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = name != null ? name.hashCode() : 0;
        result = 31 * result + type.hashCode();
        result = 31 * result + cardinality.hashCode();
        return result;
    }

    public String getName() {
        return name;
    }

    public XsdNodeType getType() {
        return type;
    }

    public XsdNodeCardinality getCardinality() {
        return cardinality;
    }

    @Override
    public String toString() {
        return "XmlItem{" +
                "'" + name + '\'' +
                ", " + type +
                ", " + cardinality +
                '}';
    }

    public String getLastNameOfPath() {
        final String[] split = getName().split("/");
        final String xmlName = split[split.length - 1];
        return xmlName;
    }

}
