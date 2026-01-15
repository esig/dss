package eu.europa.esig.dss.xml.common.xpath;

import eu.europa.esig.dss.xml.common.definition.DSSAttribute;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.xpath.item.XPathQueryAnyItem;
import eu.europa.esig.dss.xml.common.xpath.item.XPathQueryAttributeItem;
import eu.europa.esig.dss.xml.common.xpath.item.XPathQueryAttributeParameter;
import eu.europa.esig.dss.xml.common.xpath.item.XPathQueryIdentifierParameter;
import eu.europa.esig.dss.xml.common.xpath.item.XPathQueryElementItem;
import eu.europa.esig.dss.xml.common.xpath.item.XPathQueryEndItem;
import eu.europa.esig.dss.xml.common.xpath.item.XPathQueryItem;
import eu.europa.esig.dss.xml.common.xpath.item.XPathQueryNotChildOfParameter;
import eu.europa.esig.dss.xml.common.xpath.item.XPathQueryParameter;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Helper class for building an XPath expression query {@code eu.europa.esig.dss.xml.common.xpath.XPathQuery}
 * 
 */
public class XPathQueryBuilder {

    /**
     * Defines if to start search from the current position
     * <p>
     * Default: false
     */
    private boolean fromCurrentPosition;

    /**
     * Defines if to search all occurrences
     * <p>
     * Default: false
     */
    private boolean all;

    /**
     * The elements path
     */
    private DSSElement[] elements;

    /**
     * The attribute to search
     */
    private DSSAttribute attribute;

    /**
     * The attribute value, when required
     */
    private String attributeValue;

    /**
     * Defines that the looking element should not be a parent of this element
     */
    private DSSElement notChildOf;

    /**
     * ID Value to extract an element for
     */
    private String idValue;

    /**
     * Empty constructor instantiating object with empty configuration
     */
    protected XPathQueryBuilder() {
        // empty
    }

    /**
     * Instantiates an XPath from the current position
     *
     * @return {@link XPathQueryBuilder}
     */
    public static XPathQueryBuilder fromCurrentPosition() {
        return new XPathQueryBuilder().fromCurrentPosition(true);
    }

    /**
     * Defines if to start XPath from the current position
     *
     * @param fromCurrentPosition if to start XPath from the current position
     * @return this {@link XPathQueryBuilder}
     */
    public XPathQueryBuilder fromCurrentPosition(boolean fromCurrentPosition) {
        this.fromCurrentPosition = fromCurrentPosition;
        return this;
    }

    /**
     * Instantiates an XPath to search all element occurrences
     *
     * @return {@link XPathQueryBuilder}
     */
    public static XPathQueryBuilder all() {
        return new XPathQueryBuilder().all(true);
    }

    /**
     * Defines if to search all element occurrences
     *
     * @param all if to search all element occurrences
     * @return this {@link XPathQueryBuilder}
     */
    public XPathQueryBuilder all(boolean all) {
        this.all = all;
        return this;
    }

    /**
     * Instantiates an XPath to search all element occurrences from the current position
     *
     * @return {@link XPathQueryBuilder}
     */
    public static XPathQueryBuilder allFromCurrentPosition() {
        return new XPathQueryBuilder().all(true).fromCurrentPosition(true);
    }

    /**
     * Instantiates {@code XPathQueryBuilder} from the existing {@code xPathQuery}.
     * This method will create a new {@code XPathQuery}, and when any setters are used,
     * they will override the existing values.
     *
     * @param xPathQuery {@link XPathQuery} to instantiate a builder from
     * @return {@link XPathQueryBuilder}
     */
    public static XPathQueryBuilder fromXPathQuery(XPathQuery xPathQuery) {
        Objects.requireNonNull(xPathQuery, "XPathQuery cannot be null!");

        final XPathQueryBuilder builder = new XPathQueryBuilder()
                .fromCurrentPosition(xPathQuery.isFromCurrentPosition()).all(xPathQuery.isAll());

        if (xPathQuery.isEmpty()) {
            return builder;
        }

        List<DSSElement> elementList = new ArrayList<>();

        XPathQueryItem queryItem = xPathQuery.getFirstXPathQueryItem();
        while (queryItem != null) {
            if (queryItem instanceof XPathQueryAnyItem) {
                // continue

            } else if (queryItem instanceof XPathQueryAttributeItem) {
                builder.attribute(((XPathQueryAttributeItem) queryItem).getAttribute());

            } else if (queryItem instanceof XPathQueryElementItem) {
                elementList.add(((XPathQueryElementItem) queryItem).getElement());

            } else if (queryItem instanceof XPathQueryEndItem) {
                break;

            } else {
                throw new UnsupportedOperationException(String.format("The XPathQueryItem of type '%s' is " +
                        "not supported by the XPathQueryBuilder implementation!", queryItem.getClass().getSimpleName()));
            }

            XPathQueryItem nextItem = queryItem.nextItem();

            List<XPathQueryParameter> parameters = queryItem.getParameters();
            if (parameters != null && !parameters.isEmpty()) {
                if (nextItem == null) {
                    for (XPathQueryParameter parameter : parameters) {
                        if (parameter instanceof XPathQueryNotChildOfParameter) {
                            builder.notChildOf(((XPathQueryNotChildOfParameter) parameter).getParentElement());

                        } else if (parameter instanceof XPathQueryAttributeParameter) {
                            XPathQueryAttributeParameter xPathQueryByAttribute = (XPathQueryAttributeParameter) parameter;
                            builder.attribute(xPathQueryByAttribute.getAttribute(), xPathQueryByAttribute.getAttributeValue());

                        } else if (parameter instanceof XPathQueryIdentifierParameter) {
                            builder.idValue(((XPathQueryIdentifierParameter) parameter).getId());

                        } else {
                            throw new UnsupportedOperationException(String.format("The XPathQueryParameter of type '%s' is " +
                                    "not supported by the XPathQueryBuilder implementation!", parameter.getClass().getSimpleName()));
                        }
                    }

                } else {
                    throw new UnsupportedOperationException("The XPathQueryBuilder does not support parameters handling " +
                            "for any item not in the last position. Please build the XPath query chain using other options.");
                }
            }

            queryItem = nextItem;
        }


        if (!elementList.isEmpty()) {
            builder.elements(elementList.toArray(new DSSElement[0]));
        }

        return builder;
    }

    /**
     * Defines the element to search
     *
     * @param element {@link DSSElement} to search
     * @return this {@link XPathQueryBuilder}
     */
    public XPathQueryBuilder element(DSSElement element) {
        this.elements = new DSSElement[] { element };
        return this;
    }

    /**
     * Defines the element path to search
     *
     * @param elements a {@link DSSElement}s chain to search
     * @return this {@link XPathQueryBuilder}
     */
    public XPathQueryBuilder elements(DSSElement... elements) {
        this.elements = elements;
        return this;
    }

    /**
     * Defines that the looking element shall not be a parent of {@code notParentOf} element
     *
     * @param notChildOf {@link DSSElement} parent element that shall not be present
     * @return this {@link XPathQueryBuilder}
     */
    public XPathQueryBuilder notChildOf(DSSElement notChildOf) {
        this.notChildOf = notChildOf;
        return this;
    }

    /**
     * Defines the attribute to search.
     * When used, the attribute is to searched on the child of the last defined element.
     *
     * @param attribute {@link DSSAttribute}
     * @return this {@link XPathQueryBuilder}
     */
    public XPathQueryBuilder attribute(DSSAttribute attribute) {
        return attribute(attribute, null);
    }

    /**
     * Defines the attribute with the value to search.
     * When used, the attribute is to searched on the child of the last defined element.
     *
     * @param attribute {@link DSSAttribute}
     * @param attributeValue {@link String}
     * @return this {@link XPathQueryBuilder}
     */
    public XPathQueryBuilder attribute(DSSAttribute attribute, String attributeValue) {
        this.attribute = attribute;
        this.attributeValue = attributeValue;
        return this;
    }

    /**
     * Defines the id attribute value to search
     *
     * @param idValue {@link String}
     * @return this {@link XPathQueryBuilder}
     */
    public XPathQueryBuilder idValue(String idValue) {
        this.idValue = idValue;
        return this;
    }

    /**
     * Builds the XPath expression query
     *
     * @return {@link XPathQuery}
     */
    public XPathQuery build() {
        XPathQuery xPathQuery;

        if (all && fromCurrentPosition) {
            xPathQuery = new AllFromCurrentPositionXPathQuery();
        } else if (fromCurrentPosition) {
            xPathQuery = new FromCurrentPositionXPathQuery();
        } else if (all) {
            xPathQuery = new AllXPathQuery();
        } else {
            throw new UnsupportedOperationException("Unsupported operation");
        }

        XPathQueryItem lastItem = null;
        if (elements != null && elements.length > 0) {
            for (DSSElement element : elements) {
                lastItem = new XPathQueryElementItem(element);
                xPathQuery.setNextItem(lastItem);
            }
        } else {
            lastItem = new XPathQueryAnyItem();
            xPathQuery.setNextItem(lastItem);
        }

        if (notChildOf != null) {
            lastItem.addParameter(new XPathQueryNotChildOfParameter(notChildOf));
        }

        if (attribute != null) {
            if (attributeValue != null) {
                lastItem.addParameter(new XPathQueryAttributeParameter(attribute, attributeValue));
            } else {
                // @attribute is considered as independent node
                xPathQuery.setNextItem(new XPathQueryAttributeItem(attribute));
            }
        }

        if (idValue != null) {
            lastItem.addParameter(new XPathQueryIdentifierParameter(idValue));
        }

        xPathQuery.setNextItem(new XPathQueryEndItem());

        return xPathQuery;
    }
    
}
