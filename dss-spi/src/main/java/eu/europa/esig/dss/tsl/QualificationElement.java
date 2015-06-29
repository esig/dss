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
package eu.europa.esig.dss.tsl;

/**
 * This class represents a qualification element defined in the trusted list. It associates the qualification and its condition.
 *
 *
 */

public class QualificationElement {

    private String qualification;

    private Condition condition;

    /**
     * The default constructor for QualificationElement.
     */
    public QualificationElement(final String qualification, final Condition condition) {

        this.qualification = qualification;
        this.condition = condition;
    }

    /**
     * @return the condition
     */
    public Condition getCondition() {

        return condition;
    }

    /**
     * @return the qualification
     */
    public String getQualification() {

        return qualification;
    }

    /**
     * @param condition the condition to set
     */
    public void setCondition(final Condition condition) {

        this.condition = condition;
    }

    /**
     * @param qualification the qualification to set
     */
    public void setQualification(String qualification) {

        this.qualification = qualification;
    }

    @Override
    public String toString() {

        return toString("");
    }

    public String toString(String indentStr) {

        try {

            StringBuilder res = new StringBuilder();
            res.append(indentStr).append("[QualificationElement\n");
            res.append(indentStr).append("\t");
            res.append(indentStr).append("Qualification: ").append(getQualification()).append("\n");
            res.append(indentStr).append("Condition: ").append(getCondition()).append("\n");
            indentStr = indentStr.substring(1);
            res.append(indentStr + "]\n");
            return res.toString();
        } catch (Exception e) {

            return super.toString();
        }
    }
}
