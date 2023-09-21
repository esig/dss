package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.jaxb.XmlQualifier;

import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public abstract class AbstractTrustServiceConsistencyTest {

    protected final static Date PRE_EIDAS_DATE = DatatypeConverter.parseDateTime("2015-07-01T00:00:00.000Z").getTime();

    protected final static Date POST_EIDAS_DATE = DatatypeConverter.parseDateTime("2016-07-01T00:00:00.000Z").getTime();

    protected List<XmlQualifier> getXmlQualifierList(String... uris) {
        List<XmlQualifier> qualifierList = new ArrayList<>();
        for (String uri : uris) {
            XmlQualifier xmlQualifier = new XmlQualifier();
            xmlQualifier.setValue(uri);
            qualifierList.add(xmlQualifier);
        }
        return qualifierList;
    }

}
