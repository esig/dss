package eu.europa.esig.dss.xml.common.xpath;

/**
 * Gets elements matching the XPath expression starting from the current element.
 * The XPath expression path must much completely to success.
 *
 */
public class FromCurrentPositionXPathQuery extends AbstractXPathQuery {

    /** The path to search starting from the current element */
    private static final String FROM_CURRENT_POSITION_PATH = "./";

    /**
     * Default constructor
     */
    public FromCurrentPositionXPathQuery() {
        // empty
    }

    @Override
    protected String getXPathPreamble() {
        return FROM_CURRENT_POSITION_PATH;
    }

    @Override
    public boolean isAll() {
        return false;
    }

    @Override
    public boolean isFromCurrentPosition() {
        return true;
    }

}
