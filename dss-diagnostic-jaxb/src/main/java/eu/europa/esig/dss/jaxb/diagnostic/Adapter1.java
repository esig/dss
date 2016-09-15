
package eu.europa.esig.dss.jaxb.diagnostic;

import java.util.Date;
import javax.xml.bind.annotation.adapters.XmlAdapter;

public class Adapter1
    extends XmlAdapter<String, Date>
{


    public Date unmarshal(String value) {
        return (eu.europa.esig.dss.jaxb.parsers.DateParser.parse(value));
    }

    public String marshal(Date value) {
        return (eu.europa.esig.dss.jaxb.parsers.DateParser.print(value));
    }

}
