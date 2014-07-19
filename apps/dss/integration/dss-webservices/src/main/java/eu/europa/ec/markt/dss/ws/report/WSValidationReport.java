/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.ws.report;

/**
 * Wrap data of DetailedReport. Used to expose the information in the Webservice.
 *
 * @version $Revision$ - $Date$
 */

public class WSValidationReport {

    private String xmlSimpleReport;
    private String xmlDetailedReport;
    private String xmlDiagnosticData;

    /**
     * The default constructor for WSValidationReport.
     */
    public WSValidationReport() {
    }

    public String getXmlSimpleReport() {
        return xmlSimpleReport;
    }

    public void setXmlSimpleReport(String xmlSimpleReport) {
        this.xmlSimpleReport = xmlSimpleReport;
    }

    public String getXmlDetailedReport() {
        return xmlDetailedReport;
    }

    public void setXmlDetailedReport(String xmlDetailedReport) {
        this.xmlDetailedReport = xmlDetailedReport;
    }

    public String getXmlDiagnosticData() {
        return xmlDiagnosticData;
    }

    public void setXmlDiagnosticData(String xmlDiagnosticData) {
        this.xmlDiagnosticData = xmlDiagnosticData;
    }
}
