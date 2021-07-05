package eu.europa.esig.dss.validation.reports;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ReportsTest {

    @Test
    void testNullValues() {
        Reports reports = new Reports(null, null, null, null);
        assertNotNull(reports.getDiagnosticData());
        assertNull(reports.getDiagnosticData().getJaxbModel());
        assertNull(reports.getDiagnosticDataJaxb());

        assertNotNull(reports.getSimpleReport());
        assertNull(reports.getSimpleReport().getJaxbModel());
        assertNull(reports.getSimpleReportJaxb());
        assertThrows(NullPointerException.class, () -> reports.getXmlSimpleReport());

        assertNotNull(reports.getDetailedReport());
        assertNull(reports.getDetailedReport().getJAXBModel());
        assertNull(reports.getDetailedReportJaxb());
        assertThrows(NullPointerException.class, () -> reports.getXmlDetailedReport());

        assertNull(reports.getEtsiValidationReportJaxb());
        assertThrows(NullPointerException.class, () -> reports.getXmlValidationReport());
    }

}
